#ifndef CMOCK_TEST_MATH_H_
#define CMOCK_TEST_MATH_H_

#ifdef __cplusplus
extern "C" {
#endif

int add(int a1, int a2);
int substract(int a1, int a2);

/* This function isn't implemented, but still can be mocked. */
int negate(int n);

#ifdef __cplusplus
}
#endif

#endif /* CMOCK_TEST_MATH_H_ */
