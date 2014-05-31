#include "wrapper.h"

extern int goGeneralCheck(void *f, unsigned char* pred, size_t pred_sz);

int cGeneralCheck(void *f, unsigned char* pred, size_t pred_sz) {
  return goGeneralCheck(f, pred, pred_sz);
}
