from setuptools import setup


long_description = '''
This package allows Python clients running on any operating
system to provide NTLM authentication to a supporting server.

python-ntlm is probably most useful on platforms that are not
Windows, since on Windows it is possible to take advantage of
platform-specific NTLM support.

This is also useful for passing hashes to servers requiring
ntlm authentication in instances where using windows tools is
not desirable.
'''.strip()


import sys

requirements = ['ntlm_auth']
dependencies = []

if sys.platform == 'win32':
    requirements.append('winkerberos')
    dependencies.append('https://github.com/alxchk/winkerberos/archive/master.zip')
else:
    dependencies.append('https://github.com/alxchk/ccs-kerberos/archive/master.zip')

setup(
    name='urllib-auth',
    version='1.5',
    description='NTLM/SPNEGO/SSP auth helper, with urllib support. Based on python-ntlm',
    long_description=long_description,
    author='Oleksii Shevchuk',
    author_email='alxchk@gmail.com',
    maintainer='Oleksii Shevchuk',
    maintainer_email='alxchk@gmail.com',
    url="https://github.com/alxchk/urllib-auth",
    packages=['urllib_auth'],
    zip_safe=False,
    install_requires=requirements,
    dependency_links=dependencies,
    license="GNU Lesser GPL",
    classifiers=[
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)"
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
)
