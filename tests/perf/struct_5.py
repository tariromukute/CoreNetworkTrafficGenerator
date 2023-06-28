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
        a = A()
        b = B()
        c = C()
        d = D()
        e = E()
        f = F()
        g = G()
        h = H()
        i = I()
        j = J()
        k = K()
        l = L()
        m = M()
        n = N()
        o = O()
        p = P()
        q = Q()
        r = R()
        s = S()
        t = T()
        u = U()
        v = V()
        w = W()
        x = X()
        y = Y()
        z = Z()

        self.dispatcher = {
            0 : a.run,
            1 : b.run,
            2 : c.run,
            3 : d.run,
            4 : e.run,
            5 : f.run,
            6 : g.run,
            7 : h.run,
            8 : i.run,
            9 : j.run,
            10 : k.run,
            11 : l.run,
            12 : m.run,
            13 : n.run,
            14 : o.run,
            15 : p.run,
            16 : q.run,
            17 : r.run,
            18 : s.run,
            19 : t.run,
            20 : u.run,
            21 : v.run,
            22 : w.run,
            23 : x.run,
            24 : y.run,
            25 : z.run
        }
        
    def select(self, k):
        return self.dispatcher[k]()
    
    def run(self):
        for i in range(100):
            self.select(i % 26)

a = Test()
t = timeit.Timer(setup='from __main__ import a', stmt='a.run()')
print(t.timeit())