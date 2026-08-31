// A dependency-free, C-compatible C++ input for measuring treereduce-c's
// normal use case. Keeping the syntax in the C/C++ intersection avoids parser
// errors in treereduce-c while the interestingness check still uses clang++.
//
// The interestingness test is simply successful compilation and linking:
//
//   clang++ -O0 @@.cpp -o /dev/null
//
// Linking (rather than -fsyntax-only) matters: an empty translation unit is
// valid C++, but it cannot produce an executable because it has no main().

static int step_00(int value) { return (value + 3) ^ 0x0011; }
static int step_01(int value) { return (value + 5) ^ 0x0023; }
static int step_02(int value) { return (value + 7) ^ 0x0037; }
static int step_03(int value) { return (value + 11) ^ 0x0041; }
static int step_04(int value) { return (value + 13) ^ 0x0053; }
static int step_05(int value) { return (value + 17) ^ 0x0067; }
static int step_06(int value) { return (value + 19) ^ 0x0071; }
static int step_07(int value) { return (value + 23) ^ 0x0083; }
static int step_08(int value) { return (value + 29) ^ 0x0097; }
static int step_09(int value) { return (value + 31) ^ 0x0101; }
static int step_10(int value) { return (value + 37) ^ 0x0113; }
static int step_11(int value) { return (value + 41) ^ 0x0127; }
static int step_12(int value) { return (value + 43) ^ 0x0131; }
static int step_13(int value) { return (value + 47) ^ 0x0143; }
static int step_14(int value) { return (value + 53) ^ 0x0157; }
static int step_15(int value) { return (value + 59) ^ 0x0161; }
static int step_16(int value) { return (value + 61) ^ 0x0173; }
static int step_17(int value) { return (value + 67) ^ 0x0187; }
static int step_18(int value) { return (value + 71) ^ 0x0191; }
static int step_19(int value) { return (value + 73) ^ 0x0203; }
static int step_20(int value) { return (value + 79) ^ 0x0217; }
static int step_21(int value) { return (value + 83) ^ 0x0221; }
static int step_22(int value) { return (value + 89) ^ 0x0233; }
static int step_23(int value) { return (value + 97) ^ 0x0247; }
static int step_24(int value) { return (value + 101) ^ 0x0251; }
static int step_25(int value) { return (value + 103) ^ 0x0263; }
static int step_26(int value) { return (value + 107) ^ 0x0277; }
static int step_27(int value) { return (value + 109) ^ 0x0281; }
static int step_28(int value) { return (value + 113) ^ 0x0293; }
static int step_29(int value) { return (value + 127) ^ 0x0307; }
static int step_30(int value) { return (value + 131) ^ 0x0311; }
static int step_31(int value) { return (value + 137) ^ 0x0323; }
static int step_32(int value) { return (value + 139) ^ 0x0337; }
static int step_33(int value) { return (value + 149) ^ 0x0341; }
static int step_34(int value) { return (value + 151) ^ 0x0353; }
static int step_35(int value) { return (value + 157) ^ 0x0367; }
static int step_36(int value) { return (value + 163) ^ 0x0371; }
static int step_37(int value) { return (value + 167) ^ 0x0383; }
static int step_38(int value) { return (value + 173) ^ 0x0397; }
static int step_39(int value) { return (value + 179) ^ 0x0401; }
static int step_40(int value) { return (value + 181) ^ 0x0413; }
static int step_41(int value) { return (value + 191) ^ 0x0427; }
static int step_42(int value) { return (value + 193) ^ 0x0431; }
static int step_43(int value) { return (value + 197) ^ 0x0443; }
static int step_44(int value) { return (value + 199) ^ 0x0457; }
static int step_45(int value) { return (value + 211) ^ 0x0461; }
static int step_46(int value) { return (value + 223) ^ 0x0473; }
static int step_47(int value) { return (value + 227) ^ 0x0487; }
static int step_48(int value) { return (value + 229) ^ 0x0491; }
static int step_49(int value) { return (value + 233) ^ 0x0503; }
static int step_50(int value) { return (value + 239) ^ 0x0517; }
static int step_51(int value) { return (value + 241) ^ 0x0521; }
static int step_52(int value) { return (value + 251) ^ 0x0533; }
static int step_53(int value) { return (value + 257) ^ 0x0547; }
static int step_54(int value) { return (value + 263) ^ 0x0551; }
static int step_55(int value) { return (value + 269) ^ 0x0563; }
static int step_56(int value) { return (value + 271) ^ 0x0577; }
static int step_57(int value) { return (value + 277) ^ 0x0581; }
static int step_58(int value) { return (value + 281) ^ 0x0593; }
static int step_59(int value) { return (value + 283) ^ 0x0607; }
static int step_60(int value) { return (value + 293) ^ 0x0611; }
static int step_61(int value) { return (value + 307) ^ 0x0623; }
static int step_62(int value) { return (value + 311) ^ 0x0637; }
static int step_63(int value) { return (value + 313) ^ 0x0641; }

int main(int argc, char **) {
  int value = argc;
  value = step_00(value);
  value = step_01(value);
  value = step_02(value);
  value = step_03(value);
  value = step_04(value);
  value = step_05(value);
  value = step_06(value);
  value = step_07(value);
  value = step_08(value);
  value = step_09(value);
  value = step_10(value);
  value = step_11(value);
  value = step_12(value);
  value = step_13(value);
  value = step_14(value);
  value = step_15(value);
  value = step_16(value);
  value = step_17(value);
  value = step_18(value);
  value = step_19(value);
  value = step_20(value);
  value = step_21(value);
  value = step_22(value);
  value = step_23(value);
  value = step_24(value);
  value = step_25(value);
  value = step_26(value);
  value = step_27(value);
  value = step_28(value);
  value = step_29(value);
  value = step_30(value);
  value = step_31(value);
  value = step_32(value);
  value = step_33(value);
  value = step_34(value);
  value = step_35(value);
  value = step_36(value);
  value = step_37(value);
  value = step_38(value);
  value = step_39(value);
  value = step_40(value);
  value = step_41(value);
  value = step_42(value);
  value = step_43(value);
  value = step_44(value);
  value = step_45(value);
  value = step_46(value);
  value = step_47(value);
  value = step_48(value);
  value = step_49(value);
  value = step_50(value);
  value = step_51(value);
  value = step_52(value);
  value = step_53(value);
  value = step_54(value);
  value = step_55(value);
  value = step_56(value);
  value = step_57(value);
  value = step_58(value);
  value = step_59(value);
  value = step_60(value);
  value = step_61(value);
  value = step_62(value);
  value = step_63(value);
  return value == 0x12345678;
}
