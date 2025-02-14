from setuptools import setup, find_packages

with open("README.md", "r") as mdf:
    long_description = mdf.read()

setup(
    name="phishradar",
    version="0.1.post2",
    description="Phishing domain detection from Certificate Transparency logs.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/narekb/PhishRadar",
    author="Narek Babajanyan",
    author_email="narek_babajanyan@outlook.com",
    license="Apache Software License (Apache 2.0)",
    project_urls={
        "Source": "https://github.com/narekb/PhishRadar"
    },
    classifiers=[
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Topic :: Security"
    ],
    python_requires=">=3.13",
    install_requires=["certstream", "PyYAML", "wordsegment"],
    packages=find_packages(),
    include_package_data=True,
    entry_points = {
        "console_scripts": [
            "phishradar = phishradar:main"
        ] 
    }
)