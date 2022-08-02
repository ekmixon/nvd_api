"""
An unofficial, RESTful API for NIST's NVD.
Copyright (C) 2020  plasticuproject@pm.me
"""

from flask_restful import Resource, abort
from .model import Database
from webargs import fields
from webargs.flaskparser import use_args


# Sets variable name for keyword search parameter
keyword = {'keyword' : fields.Str(missing='')}


def return_result(set, *args):

    # Helper function to return CVE JSON data
    result = []
    if not args:
        result.extend(iter(set()))
    elif len(args) == 1:
        result.extend(iter(set(args[0])))
    return result


def keyword_search(value, result):

    # Helper function to parse results for keyword argument in CVE description
    keyword_results = []
    for cve in result:
        keyword_results.extend(
            cve
            for description in cve['cve']['description']['description_data']
            if value in description['value'].lower()
        )

    return keyword_results


def check_year(year):

    # Helper function to make sure the input year is valid
    try:
        int(year)
    except ValueError:
        abort(404, message='No such endpoint exists')


class CVE(Resource):
    """Initiates the Database class, loads the correct CVE year archive
    file in memory and returns the CVE data in the file matching the given
    CVE-ID in a JSON response via a GET request.
    """

    # For the rate limiter decorator
    decorators = []

    def get(self,cve_id):
        cve_id = cve_id.upper()
        data = Database().data
        year = cve_id[4:8]
        check_year(year)
        if int(year) > 2002:
            for cve in data(year):
                if cve['cve']['CVE_data_meta']['ID'] == cve_id:
                    return cve
        else:
            for cve in data('2002'):
                if cve['cve']['CVE_data_meta']['ID'] == cve_id:
                    return cve


class CVE_Year(Resource):
    """Initiates the Database class, loads the correct CVE year archive
    file in memory and returns all CVE data in the file matching the given
    year and keyword argument in a JSON response via a GET request.
    If no keyword is given it will return all CVEs in the file.
    """

    # For the rate limiter decorator
    decorators = []

    @use_args(keyword)
    def get(self, args, year):
        data = Database().data
        check_year(year)
        if int(year) > 2002:
            result = return_result(data, year)
        elif int(year) < 2003:
            result = [
                cve
                for cve in data('2002')
                if cve['cve']['CVE_data_meta']['ID'][4:8] == str(year)
            ]

        if args['keyword'] == '':
            return result
        return keyword_search(args['keyword'].lower(), result)


class CVE_Modified(Resource):
    """Initiates the Database class, loads the 'modified' archive file in
    memory and returns all CVE data in the file matching the given
    keyword argument in a JSON response via a GET request. If no keyword
    is given it will return all CVEs in the file.
    """

    # For the rate limiter decorator
    decorators = []

    @use_args(keyword)
    def get(self, args):
        modified = Database().modified
        result = return_result(modified)
        if args['keyword'] == '':
            return result
        return keyword_search(args['keyword'].lower(), result)
        

class CVE_Recent(Resource):
    """Initiates the Database class, loads the 'recent' archive file in
    memory and returns all CVE data in the file matching the given
    keyword argument in a JSON response via a GET request. If no keyword
    is given it will return all CVEs in the file.
    """

    # For the rate limiter decorator
    decorators = []

    @use_args(keyword)
    def get(self, args):
        recent = Database().recent
        result = return_result(recent)
        if args['keyword'] == '':
            return result
        return keyword_search(args['keyword'].lower(), result)


class CVE_All(Resource):
    """Initiates the Database class, loads all CVE year archive files in
    memory and returns all the CVE data in those files matching the given
    keyword argument in a JSON response via a GET request. If no keyword
    is given it will return all CVEs in the file.
    """

    # For the rate limiter decorator
    decorators = []

    @use_args(keyword)
    def get(self, args):
        result = []
        data = Database().data
        for year in range(2002, 2021):
            result.extend(iter(data(str(year))))
        if args['keyword'] == '':
            return result
        return keyword_search(args['keyword'].lower(), result)


class Schema(Resource):
    """Initiates the Database class, loads the schema file in memory and
    returns the database schema contents in a JSON response via a GET request.
    """

    # For the rate limiter decorator
    decorators = []

    def get(self):
        schema = Database().schema
        return schema()

