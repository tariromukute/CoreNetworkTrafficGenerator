import timeit

import math

class Test:
    @staticmethod
    def a():
        return 2 * math.pi
    
    @staticmethod
    def b():
        return 2 * math.pi
    
    @staticmethod
    def c():
        return 2 * math.pi

    @staticmethod
    def d():
        return 2 * math.pi

    @staticmethod
    def e():
        return 2 * math.pi
    
    @staticmethod
    def f():
        return 2 * math.pi
    
    @staticmethod
    def g():
        return 2 * math.pi
    
    @staticmethod
    def h():
        return 2 * math.pi

    @staticmethod
    def i():
        return 2 * math.pi

    @staticmethod
    def j():
        return 2 * math.pi

    @staticmethod
    def k():
        return 2 * math.pi

    @staticmethod
    def l():
        return 2 * math.pi

    @staticmethod
    def m():
        return 2 * math.pi

    @staticmethod
    def n():
        return 2 * math.pi

    @staticmethod
    def o():
        return 2 * math.pi

    @staticmethod
    def p():
        return 2 * math.pi

    @staticmethod
    def q():
        return 2 * math.pi

    @staticmethod
    def r():
        return 2 * math.pi

    @staticmethod
    def s():
        return 2 * math.pi

    @staticmethod
    def t():
        return 2 * math.pi

    @staticmethod
    def u():
        return 2 * math.pi

    @staticmethod
    def v():
        return 2 * math.pi

    @staticmethod
    def w():
        return 2 * math.pi

    @staticmethod
    def x():
        return 2 * math.pi

    @staticmethod
    def y():
        return 2 * math.pi

    @staticmethod
    def z():
        return 2 * math.pi
    
    dispatcher = {
        0 : a,
        1 : b,
        2 : c,
        3 : d,
        4 : e,
        5 : f,
        6 : g,
        7 : h,
        8 : i,
        9 : j,
        10 : k,
        11 : l,
        12 : m,
        13 : n,
        14 : o,
        15 : p,
        16 : q,
        17 : r,
        18 : s,
        19 : t,
        20 : u,
        21 : v,
        22 : w,
        23 : x,
        24 : y,
        25 : z
    }

    @classmethod
    def select(cls, k):
        return cls.dispatcher[k]()
    
    @classmethod
    def run(cls):
        for i in range(100):
            cls.select(i % 26)


a = Test()
t = timeit.Timer(setup='from __main__ import a', stmt='a.run()')
print(t.timeit())