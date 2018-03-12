from distutils.core import setup, Extension

yescryptR16_hash_module = Extension('yescryptR16_hash', sources = ['yescryptmodule.c'])

setup (name = 'yescryptR16_hash',
       version = '1.0',
       ext_modules = [yescryptR16_hash_module])
