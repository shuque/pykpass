
# edit the following to specify where to find header files
# and libraries for the MIT Kerberos 5 distribution

include_dirs =          ['/usr/local/include']
library_dirs =          ['/usr/local/lib']
runtime_library_dirs =  ['/usr/local/lib']
libraries =             ['krb5', 'com_err']
define_macros =         []

# if using Heimdal, uncomment this
#define_macros =         [('HEIMDAL', 1)]

# if you have an older version of the MIT Kerberos 5 libraries
# (version < 1.3), you will probably need to uncomment this:
#define_macros = [('NEED_INIT_ETS', 1)]

# nothing below this line should need any modifications

from distutils.core import setup, Extension

setup(name='pykpass',
      version='0.5',
      py_modules=['kpass'],
      ext_modules=[Extension('_kpass', ['kpass.c', 'wrap_kpass.c'],
                             include_dirs=include_dirs,
                             library_dirs=library_dirs,
                             runtime_library_dirs=runtime_library_dirs,
                             libraries=libraries,
                             define_macros=define_macros)],
      description='Kerberos5 Password Verification function',
      author='Shumon Huque',
      author_email='shuque@upenn.edu',
      url='http://www.huque.com/software/pykpass/',

      long_description = \
      """pykpass is a C extension module to perform password verification
using Kerberos 5. It requires the MIT Kerberos 5 or Heimdal library""",
      )
