from setuptools import setup

setup(
   name='switchDiscovery',
   version='1.2.1.dev1',
   description='CISCO Switch Devices Discovery tool',
   author='Aniket Gole',
   author_email='roshan3133@gmail.com',
   license='MIT',
   classifiers=['Development Status :: 3 - Alpha', 
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3.4'],	
   keywords= ['Cisco Switch information Discovery'],
   url='https://github.com/roshan3133/switchDiscovery',
   packages=['switchDiscovery'], 
   install_requires=['commands', 
	'paramiko', 
	'netaddr', 
	'getpass', 
	'argparse',],
   scripts=[],
   zip_safe=True
)
