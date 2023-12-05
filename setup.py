# coding=utf-8
from setuptools import setup

setup(
    name='proto-inspect',
    description='protobuf parsing, modification, '
                'and reassembly for the repl',
    version='0.3',
    author='Kent Ross',
    author_email='k@mad.cash',
    url='https://github.com/mumbleskates/proto-inspect',
    license='MIT',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'License :: OSI Approved :: MIT License',
    ],

    py_modules=[
        'proto_inspect',
    ],

    package_dir={'': "src"},

    install_requires=[],
    extras_require={
        'test': [
            'flake8',
            'pytest-cov',
        ]
    },
)
