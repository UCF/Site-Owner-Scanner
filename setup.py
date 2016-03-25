from setuptools import setup

setup(name='smap',
      version='0.1',
      description='Map UCF sites to their current owners',
      url='https://github.com/UCF/Site-Owner-Scanner',
      author='Demetrius Ford',
      author_email='Demetrius.Ford@ucf.edu',
      license='MIT',
      packages=['smap'],
      install_requires=[
          'click',
          'grequests',
          'SQLAlchemy',
          'SQLAlchemy-Utils'
      ],
      scripts=['bin/smap'],
      classifiers=[
          'Programming Language :: Python :: 2.7',
          'Envrionment :: Console',
          'License :: OSI Approved :: MIT License',
          'Development Status :: Pre-Alpha'
      ],
      zip_safe=False)
