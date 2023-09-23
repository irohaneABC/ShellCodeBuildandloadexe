#pragma once

void* stretch_pe(char* PePath);
bool repair_BaseTable64(void* PeBuf);
bool repair_IatTable(void* PeBuf);
bool repair_BaseTable(void* PeBuf);