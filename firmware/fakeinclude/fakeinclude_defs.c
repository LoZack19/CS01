/*
 * fakeinclude_defs.c — Provide storage for extern symbols declared in the
 * fake/stub headers.  Compile and link this file when building outside
 * the real NXP SDK.
 */
#include "Lpuart_Uart_Ip.h"
#include "IntCtrl_Ip.h"

const Lpuart_Uart_Ip_UserConfigType Lpuart_Uart_Ip_xHwConfigPB_3 = {0};
const IntCtrl_Ip_CtrlConfigType IntCtrlConfig_0 = {0};
