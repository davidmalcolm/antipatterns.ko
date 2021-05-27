antipatterns.ko: the world's worst kernel module
================================================

:caution: DO NOT LOAD THIS MODULE

This kernel module contains numerous security vulnerabilities.

It is intended purely as a testbed for vulnerability detection tools.

The idea is to provide a collection of kernel code
that looks plausible, but actually contains vulnerabilities.

Caveat: this is my first ever kernel module, so I may have committed
more mistakes than I intended.

This code is intended to permanently stay out of the main kernel tree,
so that if anyone does `insmod` it, the "taint" flag will be set.

See also::

  samples/kmemleak/kmemleak-test.c
