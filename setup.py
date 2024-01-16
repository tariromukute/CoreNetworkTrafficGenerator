from setuptools import setup, Extension

xdpgen_module = Extension(
    'xdpgen',
    sources=['xdpgen.c'],
    extra_compile_args=['-g', '-O2', '-Wall'],
    libraries=['bpf'],
    library_name='xdpgen'
)

setup(
    name='xdpgen',
    version='1.0',
    ext_modules=[xdpgen_module],
)
