import timeit

import math

# Class A
class A:
    def run(self):
        return 2 * math.pi

# Class B
class B:
    def run(self):
        return 2 * math.pi

# Class C
class C:
    def run(self):
        return 2 * math.pi

# Class D
class D:
    def run(self):
        return 2 * math.pi

# Class E
class E:
    def run(self):
        return 2 * math.pi

# Class F
class F:
    def run(self):
        return 2 * math.pi

# Class G
class G:
    def run(self):
        return 2 * math.pi

# Class H
class H:
    def run(self):
        return 2 * math.pi

# Class I
class I:
    def run(self):
        return 2 * math.pi

# Class J
class J:
    def run(self):
        return 2 * math.pi

# Class K
class K:
    def run(self):
        return 2 * math.pi

# Class L
class L:
    def run(self):
        return 2 * math.pi

# Class M
class M:
    def run(self):
        return 2 * math.pi

# Class N
class N:
    def run(self):
        return 2 * math.pi

# Class O
class O:
    def run(self):
        return 2 * math.pi

# Class P
class P:
    def run(self):
        return 2 * math.pi

# Class Q
class Q:
    def run(self):
        return 2 * math.pi

# Class R
class R:
    def run(self):
        return 2 * math.pi

# Class S
class S:
    def run(self):
        return 2 * math.pi

# Class T
class T:
    def run(self):
        return 2 * math.pi

# Class U
class U:
    def run(self):
        return 2 * math.pi

# Class V
class V:
    def run(self):
        return 2 * math.pi

# Class W
class W:
    def run(self):
        return 2 * math.pi

# Class X
class X:
    def run(self):
        return 2 * math.pi

# Class Y
class Y:
    def run(self):
        return 2 * math.pi

# Class Z
class Z:
    def run(self):
        return 2 * math.pi

class Test:
    def __init__(self) -> None:
        self.dispatcher = {
            0 : A,
            1 : B,
            2 : C,
            3 : D,
            4 : E,
            5 : F,
            6 : G,
            7 : H,
            8 : I,
            9 : I,
            10 : J,
            11 : K,
            12 : L,
            13 : M,
            14 : N,
            15 : O,
            16 : P,
            17 : Q,
            18 : R,
            19 : S,
            20 : T,
            21 : U,
            22 : V,
            23 : W,
            24 : X,
            25 : Y,
            26 : Z
        }
        
    def select(self, k):
        return self.dispatcher[k]()
    
    def run(self):
        for i in range(100):
            ngap_proc = self.select(i % 26)
            ngap_proc.run()

a = Test()
t = timeit.Timer(setup='from __main__ import a', stmt='a.run()')
print(t.timeit())