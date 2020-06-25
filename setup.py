from setuptools import setup

with open('README.md') as f:
    long_description = f.read()

setup(
    name='Flask-Cognito',
    version='1.15',
    url='https://github.com/jetbridge/flask_cognito',
    license='ABRMS',
    author='Mischa Spiegelmock',
    author_email='mischa@mvstg.biz',
    description='Authenticate users to Cognito user pool via JWT.',
    long_description=long_description,
    long_description_content_type='text/markdown',
    py_modules=['flask_cognito'],
    # if you would be using a package instead use packages instead
    # of py_modules:
    # packages=['flask_sqlite3'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Flask',
        # 'cognitojwt[sync]>=1.1.0',
        'cognitojwt>=1.1.0',
        'werkzeug',
        'requests',
    ],
    keywords='flask aws cognito jwt authentication auth serverless',
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
