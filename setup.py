from setuptools import setup
from pip.req import parse_requirements

install_reqs = parse_requirements('requirements.txt', session=False)
requirements = [str(pkg.req) for pkg in install_reqs]

setup(name='smap',
      version='0.1',
      description='Map UCF sites to their current owners',
      url='https://github.com/UCF/Site-Owner-Scanner',
      author='Demetrius Ford',
      author_email='Demetrius.Ford@ucf.edu',
      license='MIT',
      packages=['smap'],
      install_requires=requirements,
      scripts=['bin/smap'],
      zip_safe=False)
