import timeit
import math

class Test:

    def __init__(self) -> None:
        self.dispatcher = {
            0: self.a,
            1: self.b,
            2: self.c,
            3: self.d,
            4: self.e,
            5: self.f,
            6: self.g,
            7: self.h,
            8: self.i,
            9: self.j,
            10: self.k,
            11: self.l,
            12: self.m,
            13: self.n,
            14: self.o,
            15: self.p,
            16: self.q,
            17: self.r,
            18: self.s,
            19: self.t,
            20: self.u,
            21: self.v,
            22: self.w,
            23: self.x,
            24: self.y,
            25: self.z
        }

    def select(self, k):
        return self.dispatcher[k]()

    # Function A
    def a(self):
        return 2 * math.pi

    # Function B
    def b(self):
        return 2 * math.pi

    # Function C
    def c(self):
        return 2 * math.pi

    # Function D
    def d(self):
        return 2 * math.pi

    # Function E
    def e(self):
        return 2 * math.pi

    # Function F
    def f(self):
        return 2 * math.pi

    # Function G
    def g(self):
        return 2 * math.pi

    # Function H
    def h(self):
        return 2 * math.pi

    # Function I
    def i(self):
        return 2 * math.pi

    # Function J
    def j(self):
        return 2 * math.pi

    # Function K
    def k(self):
        return 2 * math.pi

    # Function L
    def l(self):
        return 2 * math.pi

    # Function M
    def m(self):
        return 2 * math.pi

    # Function N
    def n(self):
        return 2 * math.pi

    # Function O
    def o(self):
        return 2 * math.pi

    # Function P
    def p(self):
        return 2 * math.pi

    # Function Q
    def q(self):
        return 2 * math.pi

    # Function R
    def r(self):
        return 2 * math.pi

    # Function S
    def s(self):
        return 2 * math.pi

    # Function T
    def t(self):
        return 2 * math.pi

    # Function U
    def u(self):
        return 2 * math.pi

    # Function V
    def v(self):
        return 2 * math.pi

    # Function W
    def w(self):
        return 2 * math.pi

    # Function X
    def x(self):
        return 2 * math.pi

    # Function Y
    def y(self):
        return 2 * math.pi

    # Function Z
    def z(self):
        return 2 * math.pi
    
    def run(self):
        for i in range(100):
            self.select(i % 26)

a = Test()
t = timeit.Timer(setup='from __main__ import a', stmt='a.run()')
print(t.timeit())