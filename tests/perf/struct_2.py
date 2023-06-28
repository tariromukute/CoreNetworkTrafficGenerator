import timeit
import math

# Function A
def a():
    return 2 * math.pi

# Function B
def b():
    return 2 * math.pi

# Function C
def c():
    return 2 * math.pi

# Function D
def d():
    return 2 * math.pi

# Function E
def e():
    return 2 * math.pi

# Function F
def f():
    return 2 * math.pi

# Function G
def g():
    return 2 * math.pi

# Function H
def h():
    return 2 * math.pi

# Function I
def i():
    return 2 * math.pi

# Function J
def j():
    return 2 * math.pi

# Function K
def k():
    return 2 * math.pi

# Function L
def l():
    return 2 * math.pi

# Function M
def m():
    return 2 * math.pi

# Function N
def n():
    return 2 * math.pi

# Function O
def o():
    return 2 * math.pi

# Function P
def p():
    return 2 * math.pi

# Function Q
def q():
    return 2 * math.pi

# Function R
def r():
    return 2 * math.pi

# Function S
def s():
    return 2 * math.pi

# Function T
def t():
    return 2 * math.pi

# Function U
def u():
    return 2 * math.pi

# Function V
def v():
    return 2 * math.pi

# Function W
def w():
    return 2 * math.pi

# Function X
def x():
    return 2 * math.pi

# Function Y
def y():
    return 2 * math.pi

# Function Z
def z():
    return 2 * math.pi

class Test:

    def __init__(self) -> None:
        
        self.dispatcher = {
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

    def select(self, k):
        return self.dispatcher[k]()

    def run(self):
        for i in range(100):
            self.select(i % 26)

a = Test()
t = timeit.Timer(setup='from __main__ import a', stmt='a.run()')
print(t.timeit())