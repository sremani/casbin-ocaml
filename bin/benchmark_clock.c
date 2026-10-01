/* Verification-only POSIX monotonic timer; no production library dependency. */
#include <time.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>

CAMLprim value casbin_benchmark_monotonic(value unit)
{
    CAMLparam1(unit);
    struct timespec measured;
    if (clock_gettime(CLOCK_MONOTONIC, &measured) != 0)
        caml_failwith("benchmark monotonic clock failed");
    CAMLreturn(caml_copy_double((double)measured.tv_sec + (double)measured.tv_nsec / 1e9));
}
