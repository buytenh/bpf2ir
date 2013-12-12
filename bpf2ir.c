/*
 * TBD:
 * - verify that all opcodes are translated correctly
 * - 8/16/32 bit ssa value tracking
 * - minimise zero extension in generated assembly
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#include <linux/filter.h>

struct insn {
	uint16_t	code;
	uint8_t		jt;
	uint8_t		jf;
	uint32_t	k;
};

enum vartype {
	TYPE_UNINITIALIZED = 0,
	TYPE_CONSTANT,
	TYPE_LENGTH,
	TYPE_SSAVAR,
};

struct var {
	enum vartype	type;
	uint32_t	index;
};

enum {
	VAR_A = 0,
	VAR_X = 1,
	VAR_M0 = 2,
	VAR_COUNT = VAR_M0 + BPF_MEMWORDS,
};

struct insn_info {
	int		bb_incoming;
	int		bb_num;
	int		*in;
	struct var	vars[VAR_COUNT];
};

static void print_insn(int i, struct insn *in)
{
	switch (in->code) {
	case BPF_LD | BPF_IMM:
		printf("LD\tA, %d\n", in->k);
		break;

	case BPF_LD | BPF_W | BPF_ABS:
		printf("LD\tA, pkt[%d:4]\n", in->k);
		break;

	case BPF_LD | BPF_H | BPF_ABS:
		printf("LD\tA, pkt[%d:2]\n", in->k);
		break;

	case BPF_LD | BPF_B | BPF_ABS:
		printf("LD\tA, pkt[%d:1]\n", in->k);
		break;

	case BPF_LD | BPF_W | BPF_IND:
		printf("LD\tA, pkt[X+%d:4]\n", in->k);
		break;

	case BPF_LD | BPF_H | BPF_IND:
		printf("LD\tA, pkt[X+%d:2]\n", in->k);
		break;

	case BPF_LD | BPF_B | BPF_IND:
		printf("LD\tA, pkt[X+%d:1]\n", in->k);
		break;

	case BPF_LD | BPF_MEM:
		printf("LD\tA, M[%d]\n", in->k);
		break;

	case BPF_LD | BPF_W | BPF_LEN:
		printf("LD\tA, pktlen\n");
		break;

	case BPF_LDX | BPF_W | BPF_IMM:
		printf("LDX\tX, %d\n", in->k);
		break;

	case BPF_LDX | BPF_W | BPF_MEM:
		printf("LDX\tX, M[%d]\n", in->k);
		break;

	case BPF_LDX | BPF_W | BPF_LEN:
		printf("LDX\tX, pktlen\n");
		break;

	case BPF_LDX | BPF_B | BPF_MSH:
		printf("LDX\tX, 4 * (pkt[%d:1] & 0x0f)\n", in->k);
		break;

	case BPF_ST:
		printf("ST\tM[%d], A\n", in->k);
		break;

	case BPF_STX:
		printf("STX\tM[%d], X\n", in->k);
		break;

	case BPF_ALU | BPF_ADD | BPF_K:
		printf("ADD\tA, %d\n", in->k);
		break;

	case BPF_ALU | BPF_SUB | BPF_K:
		printf("SUB\tA, %d\n", in->k);
		break;

	case BPF_ALU | BPF_MUL | BPF_K:
		printf("MUL\tA, %d\n", in->k);
		break;

	case BPF_ALU | BPF_DIV | BPF_K:
		printf("DIV\tA, %d\n", in->k);
		break;

	case BPF_ALU | BPF_OR | BPF_K:
		printf("OR\tA, %d\n", in->k);
		break;

	case BPF_ALU | BPF_AND | BPF_K:
		printf("AND\tA, %d\n", in->k);
		break;

	case BPF_ALU | BPF_LSH | BPF_K:
		printf("LSH\tA, %d\n", in->k);
		break;

	case BPF_ALU | BPF_RSH | BPF_K:
		printf("RSH\tA, %d\n", in->k);
		break;

	case BPF_ALU | BPF_NEG:
		printf("NEG\tA\n");
		break;

	case BPF_ALU | BPF_MOD | BPF_K:
		printf("MOD\tA, %d\n", in->k);
		break;

	case BPF_ALU | BPF_XOR | BPF_K:
		printf("XOR\tA, %d\n", in->k);
		break;

	case BPF_ALU | BPF_ADD | BPF_X:
		printf("ADD\tA, X\n");
		break;

	case BPF_ALU | BPF_SUB | BPF_X:
		printf("SUB\tA, X\n");
		break;

	case BPF_ALU | BPF_MUL | BPF_X:
		printf("MUL\tA, X\n");
		break;

	case BPF_ALU | BPF_DIV | BPF_X:
		printf("DIV\tA, X\n");
		break;

	case BPF_ALU | BPF_OR | BPF_X:
		printf("OR\tA, X\n");
		break;

	case BPF_ALU | BPF_AND | BPF_X:
		printf("AND\tA, X\n");
		break;

	case BPF_ALU | BPF_LSH | BPF_X:
		printf("LSH\tA, X\n");
		break;

	case BPF_ALU | BPF_RSH | BPF_X:
		printf("RSH\tA, X\n");
		break;

	case BPF_ALU | BPF_MOD | BPF_X:
		printf("MOD\tA, X\n");
		break;

	case BPF_ALU | BPF_XOR | BPF_X:
		printf("XOR\tA, X\n");
		break;

	case BPF_JMP | BPF_JA:
		printf("JA\t%d\n", i + in->k + 1);
		break;

	case BPF_JMP | BPF_JEQ | BPF_K:
		printf("JEQ\t0x%x, %d, %d\n", in->k, i + in->jt + 1, i + in->jf + 1);
		break;

	case BPF_JMP | BPF_JGT | BPF_K:
		printf("JGT\t0x%x, %d, %d\n", in->k, i + in->jt + 1, i + in->jf + 1);
		break;

	case BPF_JMP | BPF_JGE | BPF_K:
		printf("JGE\t0x%x, %d, %d\n", in->k, i + in->jt + 1, i + in->jf + 1);
		break;

	case BPF_JMP | BPF_JSET | BPF_K:
		printf("JSET\t0x%x, %d, %d\n", in->k, i + in->jt + 1, i + in->jf + 1);
		break;

	case BPF_JMP | BPF_JEQ | BPF_X:
		printf("JEQ\tX, %d, %d\n", i + in->jt + 1, i + in->jf + 1);
		break;

	case BPF_JMP | BPF_JGT | BPF_X:
		printf("JGT\tX, %d, %d\n", i + in->jt + 1, i + in->jf + 1);
		break;

	case BPF_JMP | BPF_JGE | BPF_X:
		printf("JGE\tX, %d, %d\n", i + in->jt + 1, i + in->jf + 1);
		break;

	case BPF_JMP | BPF_JSET | BPF_X:
		printf("JSET\tX, %d, %d\n", i + in->jt + 1, i + in->jf + 1);
		break;

	case BPF_RET | BPF_K:
		printf("RET\t%d\n", in->k);
		break;

	case BPF_RET | BPF_A:
		printf("RET\tA\n");
		break;

	case BPF_MISC | BPF_TAX:
		printf("MOV\tX, A\n");
		break;

	case BPF_MISC | BPF_TXA:
		printf("MOV\tA, X\n");
		break;

	default:
		printf("unknown insn %.2x\n", in->code);
		break;
	}
}


#define N	65536

static int insns;
static struct insn prog[N];
static struct insn_info pinfo[N];
static int ssavar;

static void print_insns(void)
{
	int i;

	for (i = 0; i < insns; i++) {
		printf("; %d:\t", i);
		print_insn(i, &prog[i]);
	}
	printf("\n");
}

static void jump_count_incoming(int from, int rel)
{
	int to = from + rel + 1;

	if (to < insns)
		pinfo[to].bb_incoming++;
}

static void count_jumps(void)
{
	int i;

	for (i = 0; i < insns; i++) {
		struct insn *in = &prog[i];

		switch (in->code) {
		case BPF_JMP | BPF_JA:
			jump_count_incoming(i, in->k);
			break;

		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JSET | BPF_X:
			jump_count_incoming(i, in->jt);
			jump_count_incoming(i, in->jf);
			break;
		}
	}
}

static void assign_basic_blocks(void)
{
	int bb;
	int i;

	bb = 1;

	for (i = 0; i < insns; i++) {
		struct insn_info *info = &pinfo[i];

		if (info->bb_incoming)
			bb++;
		info->bb_num = bb;
	}
}

static void jump_log_incoming(int from, int rel)
{
	int to = from + rel + 1;

	if (to < insns) {
		struct insn_info *info = &pinfo[to];
		int i;

		for (i = 0; i < info->bb_incoming; i++) {
			if (info->in[i] == -1) {
				info->in[i] = from;
				break;
			}
		}

		if (i == info->bb_incoming) {
			printf("error!\n");
			exit(1);
		}
	}
}

static void trace_jumps(void)
{
	int num_incoming;
	int i;
	int *in;

	num_incoming = 0;
	for (i = 0; i < insns; i++)
		num_incoming += pinfo[i].bb_incoming;

	in = malloc(num_incoming * sizeof(*in));
	if (in == NULL)
		exit(1);

	for (i = 0; i < num_incoming; i++)
		in[i] = -1;

	for (i = 0; i < insns; i++) {
		struct insn_info *info = &pinfo[i];

		if (info->bb_incoming) {
			info->in = in;
			in += info->bb_incoming;
		}
	}

	for (i = 0; i < insns; i++) {
		struct insn *in = &prog[i];

		switch (in->code) {
		case BPF_JMP | BPF_JA:
			jump_log_incoming(i, in->k);
			break;

		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JSET | BPF_X:
			jump_log_incoming(i, in->jt);
			jump_log_incoming(i, in->jf);
			break;
		}
	}
}

static void output_var(struct var *v)
{
	switch (v->type) {
	case TYPE_UNINITIALIZED:
		printf("undef");
		break;

	case TYPE_CONSTANT:
		printf("%d", v->index);
		break;

	case TYPE_LENGTH:
		printf("%%len");
		break;

	case TYPE_SSAVAR:
		printf("%%%d", v->index);
		break;

	default:
		printf("invalid var type!\n");
		exit(1);
	}
}

static int output_phi(struct insn_info *info, int var)
{
	struct var *fa = &pinfo[info->in[0]].vars[var];
	int i;

	for (i = 1; i < info->bb_incoming; i++) {
		struct var *fb = &pinfo[info->in[i]].vars[var];

		if (fa->type != fb->type || fa->index != fb->index)
			break;
	}

	if (i == info->bb_incoming) {
		info->vars[var] = *fa;
		return 0;
	}

	info->vars[var].type = TYPE_SSAVAR;
	info->vars[var].index = ssavar;

	printf("\t%%%d = phi i32", ssavar);
	for (i = 0; i < info->bb_incoming; i++) {
		struct insn_info *from = &pinfo[info->in[i]];

		if (i)
			printf(",");
		printf(" [ ");
		output_var(&from->vars[var]);
		printf(", %%b%d ]", from->bb_num);
	}
	printf("\n");

	ssavar++;

	return 1;
}

static void start_bb(struct insn_info *info)
{
	int i;
	int nl;

	printf("\n; predecessors:");
	for (i = 0; i < info->bb_incoming; i++)
		printf(" b%d", pinfo[info->in[i]].bb_num);
	printf("\n");

	printf("b%d:\n", info->bb_num);

	nl = 0;
	for (i = 0; i < VAR_COUNT; i++)
		nl += output_phi(info, i);

	if (nl)
		printf("\n");
}

static void output_insn(int i, struct insn *in, struct insn_info *info)
{
	switch (in->code) {
	case BPF_LD | BPF_IMM:
		info->vars[VAR_A].type = TYPE_CONSTANT;
		info->vars[VAR_A].index = in->k;
		break;

	case BPF_LD | BPF_W | BPF_ABS:
		printf("\t%%%d = tail call i32 @ld32(i8* %%pkt, "
		       "i32 %%len, i32 %d)\n", ssavar, in->k);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_LD | BPF_H | BPF_ABS:
		printf("\t%%%d = tail call i32 @ld16(i8* %%pkt, "
		       "i32 %%len, i32 %d)\n", ssavar, in->k);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_LD | BPF_B | BPF_ABS:
		printf("\t%%%d = tail call i32 @ld8(i8* %%pkt, "
		       "i32 %%len, i32 %d)\n", ssavar, in->k);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_LD | BPF_W | BPF_IND:
		printf("\t%%%d = add i32 ", ssavar);
		output_var(&info->vars[VAR_X]);
		printf(", %d\n", in->k);

		printf("\t%%%d = tail call i32 @ld32(i8* %%pkt, "
		       "i32 %%len, i32 %%%d)\n", ssavar + 1, ssavar);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar + 1;

		ssavar += 2;
		break;

	case BPF_LD | BPF_H | BPF_IND:
		printf("\t%%%d = add i32 ", ssavar);
		output_var(&info->vars[VAR_X]);
		printf(", %d\n", in->k);

		printf("\t%%%d = tail call i32 @ld16(i8* %%pkt, "
		       "i32 %%len, i32 %%%d)\n", ssavar + 1, ssavar);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar + 1;

		ssavar += 2;
		break;

	case BPF_LD | BPF_B | BPF_IND:
		printf("\t%%%d = add i32 ", ssavar);
		output_var(&info->vars[VAR_X]);
		printf(", %d\n", in->k);

		printf("\t%%%d = tail call i32 @ld8(i8* %%pkt, "
		       "i32 %%len, i32 %%%d)\n", ssavar + 1, ssavar);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar + 1;

		ssavar += 2;
		break;

	case BPF_LD | BPF_MEM:
		if (in->k < 0 || in->k >= BPF_MEMWORDS)
			exit(1);
		info->vars[VAR_A] = info->vars[VAR_M0 + in->k];
		break;

	case BPF_LD | BPF_W | BPF_LEN:
		info->vars[VAR_A].type = TYPE_LENGTH;
		break;

	case BPF_LDX | BPF_W | BPF_IMM:
		info->vars[VAR_X].type = TYPE_CONSTANT;
		info->vars[VAR_X].index = in->k;
		break;

	case BPF_LDX | BPF_W | BPF_MEM:
		if (in->k < 0 || in->k >= BPF_MEMWORDS)
			exit(1);
		info->vars[VAR_X] = info->vars[VAR_M0 + in->k];
		break;

	case BPF_LDX | BPF_W | BPF_LEN:
		info->vars[VAR_X].type = TYPE_LENGTH;
		break;

	case BPF_LDX | BPF_B | BPF_MSH:
		printf("\t%%%d = tail call i32 @ld8(i8* %%pkt, "
		       "i32 %%len, i32 %d)\n", ssavar, in->k);
		printf("\t%%%d = and i32 %%%d, 15\n",
		       ssavar + 1, ssavar);
		printf("\t%%%d = shl i32 %%%d, 2\n",
		       ssavar + 2, ssavar + 1);
		info->vars[VAR_X].type = TYPE_SSAVAR;
		info->vars[VAR_X].index = ssavar + 2;
		ssavar += 3;
		break;

	case BPF_ST:
		if (in->k < 0 || in->k >= BPF_MEMWORDS)
			exit(1);
		info->vars[VAR_M0 + in->k] = info->vars[VAR_A];
		break;

	case BPF_STX:
		if (in->k < 0 || in->k >= BPF_MEMWORDS)
			exit(1);
		info->vars[VAR_M0 + in->k] = info->vars[VAR_X];
		break;

	case BPF_ALU | BPF_ADD | BPF_K:
		printf("\t%%%d = add i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", %d\n", in->k);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_SUB | BPF_K:
		printf("\t%%%d = sub i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", %d\n", in->k);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_MUL | BPF_K:
		printf("\t%%%d = mul i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", %d\n", in->k);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_DIV | BPF_K:
		printf("\t%%%d = udiv i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", %d\n", in->k);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_OR | BPF_K:
		printf("\t%%%d = or i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", %d\n", in->k);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_AND | BPF_K:
		printf("\t%%%d = and i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", %d\n", in->k);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_LSH | BPF_K:
		printf("\t%%%d = shl i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", %d\n", in->k);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_RSH | BPF_K:
		printf("\t%%%d = lshr i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", %d\n", in->k);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_NEG:
		printf("\t%%%d = sub i32 0, ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf("\n");
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_MOD | BPF_K:
		printf("\t%%%d = urem i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", %d\n", in->k);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_XOR | BPF_K:
		printf("\t%%%d = xor i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", %d\n", in->k);
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_ADD | BPF_X:
		printf("\t%%%d = add i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", ");
		output_var(&info->vars[VAR_X]);
		printf("\n");
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_SUB | BPF_X:
		printf("\t%%%d = sub i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", ");
		output_var(&info->vars[VAR_X]);
		printf("\n");
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_MUL | BPF_X:
		printf("\t%%%d = mul i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", ");
		output_var(&info->vars[VAR_X]);
		printf("\n");
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_DIV | BPF_X:
		printf("\t%%%d = udiv i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", ");
		output_var(&info->vars[VAR_X]);
		printf("\n");
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_OR | BPF_X:
		printf("\t%%%d = or i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", ");
		output_var(&info->vars[VAR_X]);
		printf("\n");
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_AND | BPF_X:
		printf("\t%%%d = and i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", ");
		output_var(&info->vars[VAR_X]);
		printf("\n");
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_LSH | BPF_X:
		printf("\t%%%d = shl i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", ");
		output_var(&info->vars[VAR_X]);
		printf("\n");
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_RSH | BPF_X:
		printf("\t%%%d = lshr i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", ");
		output_var(&info->vars[VAR_X]);
		printf("\n");
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_MOD | BPF_X:
		printf("\t%%%d = urem i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", ");
		output_var(&info->vars[VAR_X]);
		printf("\n");
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_ALU | BPF_XOR | BPF_X:
		printf("\t%%%d = xor i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", ");
		output_var(&info->vars[VAR_X]);
		printf("\n");
		info->vars[VAR_A].type = TYPE_SSAVAR;
		info->vars[VAR_A].index = ssavar;
		ssavar++;
		break;

	case BPF_JMP | BPF_JA:
		printf("\tbr label %%b%d\n", pinfo[i + 1 + in->k].bb_num);
		break;

	case BPF_JMP | BPF_JEQ | BPF_K:
		printf("\t%%%d = icmp eq i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", %d\n", in->k);

		printf("\tbr i1 %%%d, ", ssavar);
		printf("label %%b%d, ", pinfo[i + 1 + in->jt].bb_num);
		printf("label %%b%d\n", pinfo[i + 1 + in->jf].bb_num);

		ssavar++;
		break;

	case BPF_JMP | BPF_JGT | BPF_K:
		printf("\t%%%d = icmp ugt i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", %d\n", in->k);

		printf("\tbr i1 %%%d, ", ssavar);
		printf("label %%b%d, ", pinfo[i + 1 + in->jt].bb_num);
		printf("label %%b%d\n", pinfo[i + 1 + in->jf].bb_num);

		ssavar++;
		break;

	case BPF_JMP | BPF_JGE | BPF_K:
		printf("\t%%%d = icmp uge i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", %d\n", in->k);

		printf("\tbr i1 %%%d, ", ssavar);
		printf("label %%b%d, ", pinfo[i + 1 + in->jt].bb_num);
		printf("label %%b%d\n", pinfo[i + 1 + in->jf].bb_num);

		ssavar++;
		break;

	case BPF_JMP | BPF_JSET | BPF_K:
		printf("\t%%%d = and i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", %d\n", in->k);

		printf("\t%%%d = icmp ne i32 %%%d, 0\n",
		       ssavar + 1, ssavar);

		printf("\tbr i1 %%%d, ", ssavar + 1);
		printf("label %%b%d, ", pinfo[i + 1 + in->jt].bb_num);
		printf("label %%b%d\n", pinfo[i + 1 + in->jf].bb_num);

		ssavar += 2;

		break;

	case BPF_JMP | BPF_JEQ | BPF_X:
		printf("\t%%%d = icmp eq i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", ");
		output_var(&info->vars[VAR_X]);
		printf("\n");

		printf("\tbr i1 %%%d, ", ssavar);
		printf("label %%b%d, ", pinfo[i + 1 + in->jt].bb_num);
		printf("label %%b%d\n", pinfo[i + 1 + in->jf].bb_num);

		ssavar++;
		break;

	case BPF_JMP | BPF_JGT | BPF_X:
		printf("\t%%%d = icmp ugt i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", ");
		output_var(&info->vars[VAR_X]);
		printf("\n");

		printf("\tbr i1 %%%d, ", ssavar);
		printf("label %%b%d, ", pinfo[i + 1 + in->jt].bb_num);
		printf("label %%b%d\n", pinfo[i + 1 + in->jf].bb_num);

		ssavar++;
		break;

	case BPF_JMP | BPF_JGE | BPF_X:
		printf("\t%%%d = icmp uge i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", ");
		output_var(&info->vars[VAR_X]);
		printf("\n");

		printf("\tbr i1 %%%d, ", ssavar);
		printf("label %%b%d, ", pinfo[i + 1 + in->jt].bb_num);
		printf("label %%b%d\n", pinfo[i + 1 + in->jf].bb_num);

		ssavar++;
		break;

	case BPF_JMP | BPF_JSET | BPF_X:
		printf("\t%%%d = and i32 ", ssavar);
		output_var(&info->vars[VAR_A]);
		printf(", ");
		output_var(&info->vars[VAR_X]);
		printf("\n");

		printf("\t%%%d = icmp ne i32 %%%d, 0\n",
		       ssavar + 1, ssavar);

		printf("\tbr i1 %%%d, ", ssavar + 1);
		printf("label %%b%d, ", pinfo[i + 1 + in->jt].bb_num);
		printf("label %%b%d\n", pinfo[i + 1 + in->jf].bb_num);

		ssavar += 2;

		break;

	case BPF_RET | BPF_K:
		printf("\tret i32 %d\n", in->k);
		break;

	case BPF_RET | BPF_A:
		printf("\tret i32 ");
		output_var(&info->vars[VAR_A]);
		printf("\n");
		break;

	case BPF_MISC | BPF_TAX:
		info->vars[VAR_X] = info->vars[VAR_A];
		break;

	case BPF_MISC | BPF_TXA:
		info->vars[VAR_A] = info->vars[VAR_X];
		break;

	default:
		printf("unknown insn %.2x\n", in->code);
		exit(1);
	}
}

static void output(void)
{
	int i;

	printf("declare i32 @ld8(i8* nocapture, i32, i32)\n");
	printf("\n");

	printf("declare i32 @ld16(i8* nocapture, i32, i32)\n");
	printf("\n");

	printf("declare i32 @ld32(i8* nocapture, i32, i32)\n");
	printf("\n");

	printf("define i32 @filter(i8* nocapture %%pkt, i32 %%len) {\n");

	ssavar = 0;

	printf("b1:\n");

	for (i = 0; i < insns; i++) {
		struct insn *in = &prog[i];
		struct insn_info *info = &pinfo[i];
		int j;

		if (info->bb_incoming) {
			start_bb(info);
		} else if (i) {
			for (j = 0; j < VAR_COUNT; j++)
				info->vars[j] = pinfo[i - 1].vars[j];
			printf("\n");
		}

		printf("\t; ");
		print_insn(i, in);

		output_insn(i, in, info);
	}

	printf("}\n");
}

int main()
{
	int ret;

	ret = read(0, prog, sizeof(prog));
	if (ret < 0) {
		perror("read");
		return 1;
	}

	insns = ret / sizeof(prog[0]);

	print_insns();

	count_jumps();
	assign_basic_blocks();
	trace_jumps();

	output();

	return 0;
}
