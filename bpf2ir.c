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
	TYPE_UNDEF = 0,
	TYPE_CONSTANT,
	TYPE_LENGTH,
	TYPE_SSAVAR,
};

struct var {
	enum vartype	type;
	union {
		uint32_t	k;
		struct {
			uint32_t	var8;
			uint32_t	var16;
			uint32_t	var32;
		};
	};
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
	i++;

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
		printf("JA\t%d\n", i + in->k);
		break;

	case BPF_JMP | BPF_JEQ | BPF_K:
		printf("JEQ\t0x%x, %d, %d\n", in->k, i + in->jt, i + in->jf);
		break;

	case BPF_JMP | BPF_JGT | BPF_K:
		printf("JGT\t0x%x, %d, %d\n", in->k, i + in->jt, i + in->jf);
		break;

	case BPF_JMP | BPF_JGE | BPF_K:
		printf("JGE\t0x%x, %d, %d\n", in->k, i + in->jt, i + in->jf);
		break;

	case BPF_JMP | BPF_JSET | BPF_K:
		printf("JSET\t0x%x, %d, %d\n", in->k, i + in->jt, i + in->jf);
		break;

	case BPF_JMP | BPF_JEQ | BPF_X:
		printf("JEQ\tX, %d, %d\n", i + in->jt, i + in->jf);
		break;

	case BPF_JMP | BPF_JGT | BPF_X:
		printf("JGT\tX, %d, %d\n", i + in->jt, i + in->jf);
		break;

	case BPF_JMP | BPF_JGE | BPF_X:
		printf("JGE\tX, %d, %d\n", i + in->jt, i + in->jf);
		break;

	case BPF_JMP | BPF_JSET | BPF_X:
		printf("JSET\tX, %d, %d\n", i + in->jt, i + in->jf);
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


static int insns;
static struct insn prog[BPF_MAXINSNS];
static struct insn_info pinfo[BPF_MAXINSNS];
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

static void for_jump(int from, int rel, void (*cb)(int from, int to))
{
	int to = from + rel + 1;

	if (to >= insns) {
		fprintf(stderr, "jump from %d to %d, while only %d insns\n",
			from, to, insns);
		exit(1);
	}

	cb(from, to);
}

static void foreach_jump(void (*cb)(int from, int to))
{
	int i;

	for (i = 0; i < insns; i++) {
		struct insn *in = &prog[i];

		switch (in->code) {
		case BPF_JMP | BPF_JA:
			for_jump(i, in->k, cb);
			break;

		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JSET | BPF_K:
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JSET | BPF_X:
			for_jump(i, in->jt, cb);
			for_jump(i, in->jf, cb);
			break;
		}
	}
}

static void jump_count_incoming(int from, int to)
{
	pinfo[to].bb_incoming++;
}

static void count_jumps(void)
{
	foreach_jump(jump_count_incoming);
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

static void jump_log_incoming(int from, int to)
{
	struct insn_info *info = &pinfo[to];
	int i;

	for (i = 0; i < info->bb_incoming; i++) {
		if (info->in[i] == -1) {
			info->in[i] = from;
			return;
		}
	}

	fprintf(stderr, "no space left in incoming jump array for "
			"basic block %d\n", to);

	exit(1);
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
	if (in == NULL) {
		fprintf(stderr, "out of memory\n");
		exit(1);
	}

	for (i = 0; i < num_incoming; i++)
		in[i] = -1;

	for (i = 0; i < insns; i++) {
		struct insn_info *info = &pinfo[i];

		if (info->bb_incoming) {
			info->in = in;
			in += info->bb_incoming;
		}
	}

	foreach_jump(jump_log_incoming);
}

static void output_var(struct var *v)
{
	switch (v->type) {
	case TYPE_UNDEF:
		printf("undef");
		break;

	case TYPE_CONSTANT:
		printf("%d", v->k);
		break;

	case TYPE_LENGTH:
		printf("%%len");
		break;

	case TYPE_SSAVAR:
		printf("%%%d", v->var32);
		break;

	default:
		fprintf(stderr, "invalid var type!\n");
		exit(1);
	}
}

static void output_zext(int tovar, int towidth, int fromvar, int fromwidth)
{
	printf("\t%%%d = zext i%d %%%d to i%d\n",
	       tovar, fromwidth, fromvar, towidth);
}

static int output_phi(struct insn_info *info, int var)
{
	struct var *fa = &pinfo[info->in[0]].vars[var];
	int i;

	for (i = 1; i < info->bb_incoming; i++) {
		struct var *fb = &pinfo[info->in[i]].vars[var];

		if (fa->type != fb->type)
			break;
		if (fa->type == TYPE_CONSTANT && fa->k != fb->k)
			break;
		if (fa->type == TYPE_SSAVAR && fa->var8 != fb->var8)
			break;
		if (fa->type == TYPE_SSAVAR && fa->var16 != fb->var16)
			break;
		if (fa->type == TYPE_SSAVAR && fa->var32 != fb->var32)
			break;
	}

	if (i == info->bb_incoming) {
		info->vars[var] = *fa;
		return 0;
	}

	info->vars[var].type = TYPE_SSAVAR;
	info->vars[var].var8 = -1;
	info->vars[var].var16 = -1;
	info->vars[var].var32 = ssavar;

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
	struct var *var_a = &info->vars[VAR_A];
	struct var *var_x = &info->vars[VAR_X];

	switch (in->code) {
	case BPF_LD | BPF_IMM:
		var_a->type = TYPE_CONSTANT;
		var_a->k = in->k;
		break;

	case BPF_LD | BPF_W | BPF_ABS:
		printf("\t%%%d = tail call i32 @ld32(i8* %%pkt, "
		       "i32 %%len, i32 %d)\n", ssavar, in->k);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_LD | BPF_H | BPF_ABS:
		printf("\t%%%d = tail call i16 @ld16(i8* %%pkt, "
		       "i32 %%len, i32 %d)\n", ssavar, in->k);
		output_zext(ssavar + 1, 32, ssavar, 16);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar + 1;
		ssavar += 2;

		break;

	case BPF_LD | BPF_B | BPF_ABS:
		printf("\t%%%d = tail call i8 @ld8(i8* %%pkt, "
		       "i32 %%len, i32 %d)\n", ssavar, in->k);
		output_zext(ssavar + 1, 32, ssavar, 8);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar + 1;
		ssavar += 2;

		break;

	case BPF_LD | BPF_W | BPF_IND:
		printf("\t%%%d = add i32 ", ssavar);
		output_var(var_x);
		printf(", %d\n", in->k);

		printf("\t%%%d = tail call i32 @ld32(i8* %%pkt, "
		       "i32 %%len, i32 %%%d)\n", ssavar + 1, ssavar);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar + 1;
		ssavar += 2;

		break;

	case BPF_LD | BPF_H | BPF_IND:
		printf("\t%%%d = add i32 ", ssavar);
		output_var(var_x);
		printf(", %d\n", in->k);

		printf("\t%%%d = tail call i16 @ld16(i8* %%pkt, "
		       "i32 %%len, i32 %%%d)\n", ssavar + 1, ssavar);
		output_zext(ssavar + 2, 32, ssavar + 1, 16);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar + 2;
		ssavar += 3;

		break;

	case BPF_LD | BPF_B | BPF_IND:
		printf("\t%%%d = add i32 ", ssavar);
		output_var(var_x);
		printf(", %d\n", in->k);

		printf("\t%%%d = tail call i8 @ld8(i8* %%pkt, "
		       "i32 %%len, i32 %%%d)\n", ssavar + 1, ssavar);
		output_zext(ssavar + 2, 32, ssavar + 1, 8);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar + 2;
		ssavar += 3;

		break;

	case BPF_LD | BPF_MEM:
		if (in->k < 0 || in->k >= BPF_MEMWORDS) {
			fprintf(stderr, "invalid memory word index\n");
			exit(1);
		}
		*var_a = info->vars[VAR_M0 + in->k];
		break;

	case BPF_LD | BPF_W | BPF_LEN:
		var_a->type = TYPE_LENGTH;
		break;

	case BPF_LDX | BPF_W | BPF_IMM:
		var_x->type = TYPE_CONSTANT;
		var_x->k = in->k;
		break;

	case BPF_LDX | BPF_W | BPF_MEM:
		if (in->k < 0 || in->k >= BPF_MEMWORDS) {
			fprintf(stderr, "invalid memory word index\n");
			exit(1);
		}
		*var_x = info->vars[VAR_M0 + in->k];
		break;

	case BPF_LDX | BPF_W | BPF_LEN:
		var_x->type = TYPE_LENGTH;
		break;

	case BPF_LDX | BPF_B | BPF_MSH:
		printf("\t%%%d = tail call i8 @ld8(i8* %%pkt, "
		       "i32 %%len, i32 %d)\n", ssavar, in->k);
		output_zext(ssavar + 1, 32, ssavar, 8);
		printf("\t%%%d = and i32 %%%d, 15\n",
		       ssavar + 2, ssavar + 1);
		printf("\t%%%d = shl i32 %%%d, 2\n",
		       ssavar + 3, ssavar + 2);

		var_x->type = TYPE_SSAVAR;
		var_x->var8 = -1;
		var_x->var16 = -1;
		var_x->var32 = ssavar + 3;
		ssavar += 4;

		break;

	case BPF_ST:
		if (in->k < 0 || in->k >= BPF_MEMWORDS) {
			fprintf(stderr, "invalid memory word index\n");
			exit(1);
		}
		info->vars[VAR_M0 + in->k] = *var_a;
		break;

	case BPF_STX:
		if (in->k < 0 || in->k >= BPF_MEMWORDS) {
			fprintf(stderr, "invalid memory word index\n");
			exit(1);
		}
		info->vars[VAR_M0 + in->k] = *var_x;
		break;

	case BPF_ALU | BPF_ADD | BPF_K:
		printf("\t%%%d = add i32 ", ssavar);
		output_var(var_a);
		printf(", %d\n", in->k);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_SUB | BPF_K:
		printf("\t%%%d = sub i32 ", ssavar);
		output_var(var_a);
		printf(", %d\n", in->k);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_MUL | BPF_K:
		printf("\t%%%d = mul i32 ", ssavar);
		output_var(var_a);
		printf(", %d\n", in->k);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_DIV | BPF_K:
		printf("\t%%%d = udiv i32 ", ssavar);
		output_var(var_a);
		printf(", %d\n", in->k);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_OR | BPF_K:
		printf("\t%%%d = or i32 ", ssavar);
		output_var(var_a);
		printf(", %d\n", in->k);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_AND | BPF_K:
		printf("\t%%%d = and i32 ", ssavar);
		output_var(var_a);
		printf(", %d\n", in->k);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_LSH | BPF_K:
		printf("\t%%%d = shl i32 ", ssavar);
		output_var(var_a);
		printf(", %d\n", in->k);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_RSH | BPF_K:
		printf("\t%%%d = lshr i32 ", ssavar);
		output_var(var_a);
		printf(", %d\n", in->k);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_NEG:
		printf("\t%%%d = sub i32 0, ", ssavar);
		output_var(var_a);
		printf("\n");

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_MOD | BPF_K:
		printf("\t%%%d = urem i32 ", ssavar);
		output_var(var_a);
		printf(", %d\n", in->k);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_XOR | BPF_K:
		printf("\t%%%d = xor i32 ", ssavar);
		output_var(var_a);
		printf(", %d\n", in->k);

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_ADD | BPF_X:
		printf("\t%%%d = add i32 ", ssavar);
		output_var(var_a);
		printf(", ");
		output_var(var_x);
		printf("\n");

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_SUB | BPF_X:
		printf("\t%%%d = sub i32 ", ssavar);
		output_var(var_a);
		printf(", ");
		output_var(var_x);
		printf("\n");

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_MUL | BPF_X:
		printf("\t%%%d = mul i32 ", ssavar);
		output_var(var_a);
		printf(", ");
		output_var(var_x);
		printf("\n");

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_DIV | BPF_X:
		printf("\t%%%d = udiv i32 ", ssavar);
		output_var(var_a);
		printf(", ");
		output_var(var_x);
		printf("\n");

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_OR | BPF_X:
		printf("\t%%%d = or i32 ", ssavar);
		output_var(var_a);
		printf(", ");
		output_var(var_x);
		printf("\n");

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_AND | BPF_X:
		printf("\t%%%d = and i32 ", ssavar);
		output_var(var_a);
		printf(", ");
		output_var(var_x);
		printf("\n");

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_LSH | BPF_X:
		printf("\t%%%d = shl i32 ", ssavar);
		output_var(var_a);
		printf(", ");
		output_var(var_x);
		printf("\n");

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_RSH | BPF_X:
		printf("\t%%%d = lshr i32 ", ssavar);
		output_var(var_a);
		printf(", ");
		output_var(var_x);
		printf("\n");

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_MOD | BPF_X:
		printf("\t%%%d = urem i32 ", ssavar);
		output_var(var_a);
		printf(", ");
		output_var(var_x);
		printf("\n");

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_ALU | BPF_XOR | BPF_X:
		printf("\t%%%d = xor i32 ", ssavar);
		output_var(var_a);
		printf(", ");
		output_var(var_x);
		printf("\n");

		var_a->type = TYPE_SSAVAR;
		var_a->var8 = -1;
		var_a->var16 = -1;
		var_a->var32 = ssavar;
		ssavar++;

		break;

	case BPF_JMP | BPF_JA:
		printf("\tbr label %%b%d\n", pinfo[i + 1 + in->k].bb_num);
		break;

	case BPF_JMP | BPF_JEQ | BPF_K:
		printf("\t%%%d = icmp eq i32 ", ssavar);
		output_var(var_a);
		printf(", %d\n", in->k);

		printf("\tbr i1 %%%d, ", ssavar);
		printf("label %%b%d, ", pinfo[i + 1 + in->jt].bb_num);
		printf("label %%b%d\n", pinfo[i + 1 + in->jf].bb_num);

		ssavar++;
		break;

	case BPF_JMP | BPF_JGT | BPF_K:
		printf("\t%%%d = icmp ugt i32 ", ssavar);
		output_var(var_a);
		printf(", %d\n", in->k);

		printf("\tbr i1 %%%d, ", ssavar);
		printf("label %%b%d, ", pinfo[i + 1 + in->jt].bb_num);
		printf("label %%b%d\n", pinfo[i + 1 + in->jf].bb_num);

		ssavar++;
		break;

	case BPF_JMP | BPF_JGE | BPF_K:
		printf("\t%%%d = icmp uge i32 ", ssavar);
		output_var(var_a);
		printf(", %d\n", in->k);

		printf("\tbr i1 %%%d, ", ssavar);
		printf("label %%b%d, ", pinfo[i + 1 + in->jt].bb_num);
		printf("label %%b%d\n", pinfo[i + 1 + in->jf].bb_num);

		ssavar++;
		break;

	case BPF_JMP | BPF_JSET | BPF_K:
		printf("\t%%%d = and i32 ", ssavar);
		output_var(var_a);
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
		output_var(var_a);
		printf(", ");
		output_var(var_x);
		printf("\n");

		printf("\tbr i1 %%%d, ", ssavar);
		printf("label %%b%d, ", pinfo[i + 1 + in->jt].bb_num);
		printf("label %%b%d\n", pinfo[i + 1 + in->jf].bb_num);

		ssavar++;
		break;

	case BPF_JMP | BPF_JGT | BPF_X:
		printf("\t%%%d = icmp ugt i32 ", ssavar);
		output_var(var_a);
		printf(", ");
		output_var(var_x);
		printf("\n");

		printf("\tbr i1 %%%d, ", ssavar);
		printf("label %%b%d, ", pinfo[i + 1 + in->jt].bb_num);
		printf("label %%b%d\n", pinfo[i + 1 + in->jf].bb_num);

		ssavar++;
		break;

	case BPF_JMP | BPF_JGE | BPF_X:
		printf("\t%%%d = icmp uge i32 ", ssavar);
		output_var(var_a);
		printf(", ");
		output_var(var_x);
		printf("\n");

		printf("\tbr i1 %%%d, ", ssavar);
		printf("label %%b%d, ", pinfo[i + 1 + in->jt].bb_num);
		printf("label %%b%d\n", pinfo[i + 1 + in->jf].bb_num);

		ssavar++;
		break;

	case BPF_JMP | BPF_JSET | BPF_X:
		printf("\t%%%d = and i32 ", ssavar);
		output_var(var_a);
		printf(", ");
		output_var(var_x);
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
		output_var(var_a);
		printf("\n");
		break;

	case BPF_MISC | BPF_TAX:
		*var_x = *var_a;
		break;

	case BPF_MISC | BPF_TXA:
		*var_a = *var_x;
		break;

	default:
		fprintf(stderr, "unknown insn %.2x\n", in->code);
		exit(1);
	}
}

static void output(void)
{
	int i;

	printf("declare i8 @ld8(i8* nocapture, i32, i32)\n");
	printf("\n");

	printf("declare i16 @ld16(i8* nocapture, i32, i32)\n");
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
