#!/usr/bin/env python2
## -*- coding: utf-8 -*-
##
##  Jonathan Salwan - 2014-11-23
## 
##  http://shell-storm.org
##  http://twitter.com/JonathanSalwan
## 
##  This program is free software: you can redistribute it and/or modify
##  it under the terms of the GNU General Public License as published by
##  the Free Software  Foundation, either  version 3 of  the License, or
##  (at your option) any later version.
##

from abf        import __NAME__, __VERSION__, __AUTHOR__, __MAIL__, __DESC__, __LICENSE__
from setuptools import setup

setup(
    author           = __AUTHOR__,
    author_email     = __MAIL__,
    description      = __DESC__,
    keywords         = 'abstract binary format manipulation elf pe mach-o',
    license          = __LICENSE__,
    name             = __NAME__,
    packages         = ['abf'],
    version          = __VERSION__,

    classifiers      = [
        'Operating System :: POSIX'
    ],
)

