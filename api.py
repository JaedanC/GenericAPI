from __future__ import annotations
from enum import Enum
from io import StringIO
import base64
import copy
import csv
import io
import ipaddress
import json
import os
import traceback
import requests
from typing import Callable, Any, List, Set


class APIResponse:
    def __init__(self, req: APIRequest, requests_resp: requests.Response):
        self.__req: APIRequest = req
        self.__requests_resp: requests.Response = requests_resp
    
    def text(self):
        return self.__requests_resp.text
    
    def json_pretty(self, indent=4):
        try:
            json_obj = json.loads(self.__requests_resp.text)
            return json.dumps(json_obj, indent=indent)
        except json.decoder.JSONDecodeError:
            return self.__requests_resp.text
    
    def json_dict(self):
        try:
            return json.loads(self.__requests_resp.text)
        except json.decoder.JSONDecodeError as e:
            print(e)
            print(self.__requests_resp.text)
            raise e
    
    def status_code(self):
        return self.__requests_resp.status_code
    
    def request(self):
        return self.__req
    
    def raw(self):
        return self.__requests_resp


class ODataResponse:
    def __init__(self, req: APIRequest, values):
        self.__req: APIRequest = req
        self.__values = values
    
    def json_dict(self):
        return self.__values
    
    def json_pretty(self, indent=4):
        return json.dumps(self.__values, indent=indent)

    def request(self):
        return self.__req


class ContentType(Enum):
    ApplicationJson = 1
    UrlEncoded = 2


class Method(Enum):
    Get = 1
    Post = 2
    Delete = 3
    Put = 4
    Patch = 5


class APIRequest:
    def __init__(self, url: str):
        self.__base_url: str = url
        self.__url: str = url
        self.__parameters: dict | None = None
        self.__content_type: ContentType | None = None
        self.__headers = {}
        self.__method: Method | None = None
        self.__query_parameters: dict | None = None
    
    def __repr__(self):
        method_text = "(No method set)"
        if self.__method == Method.Get:
            method_text = "GET"
        elif self.__method == Method.Post:
            method_text = "POST"
        elif self.__method == Method.Delete:
            method_text = "DELETE"
        elif self.__method == Method.Put:
            method_text = "PUT"
        elif self.__method == Method.Patch:
            method_text = "PATCH"
        
        content_type_text = "(No content-type set)"
        if self.__content_type == ContentType.ApplicationJson:
            content_type_text = "application/json"
        elif self.__content_type == ContentType.UrlEncoded:
            content_type_text = "application/x-www-form-urlencoded"
        
        headers = self.__headers.copy()
        if self.__content_type is not None:
            headers["Content-Type"] = content_type_text
        
        headers_text = json.dumps(headers, indent=4)


        url = self.__url
        if self.__query_parameters is not None:
            url += "?" + dict_to_url_query(self.__query_parameters)

        if self.__method == Method.Get:
            return f"{method_text} {url}\n" + \
            "Headers:\n" + \
            headers_text
        if (self.__method == Method.Post or self.__method == Method.Delete) and self.__parameters is None:
            return f"{method_text} {url}\n" + \
            "Headers:\n" + \
            headers_text
        elif self.__method == Method.Post or self.__method == Method.Delete:
            return f"{method_text} {url}\n" + \
            "Headers:\n" + \
            headers_text + "\n" + \
            "Body:\n" + \
            json.dumps(self.__parameters, indent=4)
        
    def set_method(self, method: Method):
        if self.__method is not None:
            raise ValueError("Cannot set the method twice")
        self.__method = method
        return self
    
    def set_content_type(self, content_type: ContentType):
        if self.__method == Method.Get:
            raise ValueError("Cannot set the content-type for get requests")
        if  self.__method == Method.Delete:
            raise ValueError("Cannot set the content-type for delete requests")
        self.__content_type = content_type
        return self
    
    def add_parameter(self, key: str, value):
        if key in self.__headers:
            raise ValueError("Cannot set a parameter twice")
        if self.__parameters is None:
            self.__parameters = {}
        self.__parameters[key] = value
        return self
    
    def add_parameters(self, params: dict):
        for k, v in params.items():
            self.add_parameter(k, v)
        return self
    
    def add_query(self, key, value):
        if self.__query_parameters is None:
            self.__query_parameters = {}
        self.__query_parameters[key] = value
        return self

    def add_header(self, header: str, value: str):
        self.__headers[header] = value
        return self

    def set_bearer_authorization(self, token: str):
        return self.add_header("Authorization", "Bearer " + token)
    
    def set_basic_authorization(self, user, password):
        combined = f"{user}:{password}"
        # From https://stackabuse.com/encoding-and-decoding-base64-strings-in-python/
        message_bytes = combined.encode("ascii")
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode("ascii")
        return self.add_header("Authorization", "Basic " + base64_message)
    
    def execute(self, **kwargs):
        if self.__method == None:
            raise ValueError("A method must be set")

        if self.__content_type is None and self.__parameters is not None:
            raise ValueError("A content Type must be set when using parameters")
        
        if self.__content_type is not None and self.__parameters is None:
            raise ValueError("Parameter must be added when setting a content type")

        if self.__parameters is not None and self.__method == Method.Get:
            raise ValueError("Cannot have parameters with a get request")
        
        if self.__parameters is not None and self.__method == Method.Delete:
            raise ValueError("Cannot have parameters with a delete request")
        
        if self.__content_type is not None and self.__method == Method.Get:
            raise ValueError("Cannot set the content type for a get request")
        
        if self.__content_type is not None and self.__method == Method.Delete:
            raise ValueError("Cannot set the content type for a delete request")

        body = None
        if self.__parameters is not None:
            if self.__content_type == ContentType.ApplicationJson:
                body = json.dumps(self.__parameters)
            elif self.__content_type == ContentType.UrlEncoded:
                body = dict_to_url_query(self.__parameters)
            else:
                raise ValueError("The Content type does not match a known value")
        
        # Add any queries to the URL
        if self.__content_type == ContentType.UrlEncoded and self.__query_parameters is not None:
            raise ValueError("Can't have UrlEncoded and Query parameters at the same time")
        elif self.__query_parameters is not None:
            self.__url += "?" + dict_to_url_query(self.__query_parameters)

        # Overwrite any existing is fine
        if self.__content_type == ContentType.ApplicationJson:
            self.__headers["Content-Type"] = "application/json"
        elif self.__content_type == ContentType.UrlEncoded:
            self.__headers["Content-Type"] = "application/x-www-form-urlencoded"
        
        if self.__method == Method.Get:
            return APIResponse(self, requests.get(self.__url, headers=self.__headers, **kwargs))
        elif self.__method == Method.Post:
            if body is not None:
                return APIResponse(self, requests.post(self.__url, headers=self.__headers, data=body, **kwargs))
            else:
                return APIResponse(self, requests.post(self.__url, headers=self.__headers, **kwargs))
        elif self.__method == Method.Delete:
            return APIResponse(self, requests.delete(self.__url, headers=self.__headers, **kwargs))
        elif self.__method == Method.Put:
            if body is not None:
                return APIResponse(self, requests.put(self.__url, headers=self.__headers, data=body, **kwargs))
            else:
                return APIResponse(self, requests.put(self.__url, headers=self.__headers, **kwargs))
        elif self.__method == Method.Patch:
            if body is not None:
                return APIResponse(self, requests.patch(self.__url, headers=self.__headers, data=body, **kwargs))
            else:
                return APIResponse(self, requests.patch(self.__url, headers=self.__headers, **kwargs))

    def execute_odata(self, odata_next_link_key: str | List[str], odata_value_key, url_prefix=""):
        if isinstance(odata_next_link_key, str):
            odata_next_link_key = [odata_next_link_key]
        
        results = []
        try:
            while True:
                res: APIResponse = self.execute()
                results += res.json_dict()[odata_value_key]
 
                next_link = RelaxedDictionary(res.json_dict()) \
                    .get(*odata_next_link_key)
                if next_link is None:
                    break
                   
                self.__url = self.__base_url
                # If the next_link has query parameters, then we need to make
                # the query parameters are .updated
                if "?" in next_link:
                    _, query = next_link.split("?")
                    next_link_queries = {k: v for k, v in [q.split("=") for q in query.split("&")]}
                    if self.__query_parameters is None:
                        self.__query_parameters = {}
                    self.__query_parameters.update(next_link_queries)
                    self.__url = self.__base_url + url_prefix
                else:
                    self.__url = self.__base_url + url_prefix + next_link
        except KeyboardInterrupt:
            print()
            print("Interrupting")
        return ODataResponse(self, results)


class RelaxedDictionary:
    """Use when you don't know if a key exists and you want to nest your lookup.
    """
    def __init__(self, dictionary: dict):
        assert isinstance(dictionary, dict)
        self.base = dictionary
    
    def get(self, *keys, map_function: Callable=None, default=None):
        if self.base is None:
            return default
        
        cursor = self.base
        for key in keys:
            if key not in cursor:
                return default
            
            cursor = cursor[key]
            if not isinstance(cursor, dict):
                break
        
        return cursor if map_function is None else map_function(cursor)
    
    def set(self, keys: List[str], set_key, value) -> RelaxedDictionary:
        if self.base is None:
            assert False, "Must have a base"
        
        cursor = self.base
        for key in keys:
            if key not in cursor:
                cursor[key] = {}
            
            cursor = cursor[key]
            if not isinstance(cursor, dict):
                break
        
        cursor[set_key] = value
        return self

    def get_base(self) -> dict:
        return self.base
    
    def is_empty(self):
        return len(self.base) == 0


class ListDictFilter:
    def __init__(self, data: List[dict] | List[RelaxedDictionary]):
        self.data: List[RelaxedDictionary] = []
        for entry in data:
            if isinstance(entry, RelaxedDictionary):
                self.data.append(entry)
            elif isinstance(entry, dict):
                self.data.append(RelaxedDictionary(entry))
            else:
                assert False, "Must be a list of dict or RelaxedDictionary"
        self.n_next_filters_or = 0
        self.n_next_filters_keep_rows: Set[RelaxedDictionary] = set()
    
    def filter_or(self, n_next_filters_or: int) -> ListDictFilter:
        assert isinstance(n_next_filters_or, int)
        assert 0 < n_next_filters_or, "Must be a positive integer"
        self.n_next_filters_or = n_next_filters_or
        return self

    def filter(self, keys: List[str] | str, value: List[Any] | Any) -> ListDictFilter:
        if not isinstance(value, list):
            value = [value]
        return self.filter_function(keys, lambda x: x in value)
    
    def has_key(self, keys: List[str] | str) -> ListDictFilter:
        return self.filter_function(keys, lambda x: x is not None)

    def filter_function(
            self,
            keys: List[str] | str,
            func: Callable[[Any], bool],
            *args,
            **kwargs
        ) -> ListDictFilter:
        if not isinstance(keys, list):
            keys = [keys]
        
        filtered_data = [e for e in self.data if func(e.get(*keys), *args, **kwargs)]

        if self.n_next_filters_or == 0:
            self.data = filtered_data
            return self
        
        # If filter_or has been set then we need to keep track of the rows that
        # have previous passed the filter. Only when n_next_filters_or is 0
        # should be set the internal data to the rows that pass. We can use a
        # running set to keep track of what has passed previous filters.

        # This method means that n_next_filters should be 0 when we call compile
        # or we may not be filtered how we expect.
        self.n_next_filters_or -= 1
        if self.n_next_filters_or == 0:
            self.data = list(self.n_next_filters_keep_rows | set(filtered_data))
            self.n_next_filters_keep_rows = set()
            return self
        else:
            self.n_next_filters_keep_rows = self.n_next_filters_keep_rows | set(filtered_data)
            return self

    def compile(self) -> List[RelaxedDictionary]:
        assert self.n_next_filters_or == 0, "You have not filtered n times after the or"
        return [r for r in self.data]

    def compile_no_relaxed(self) -> List[dict]:
        assert self.n_next_filters_or == 0, "You have not filtered n times after the or"
        return [r.get_base() for r in self.data]

    def compile_single(self, allow_duplicates=False, must_find=False) -> RelaxedDictionary:
        assert self.n_next_filters_or == 0, "You have not filtered n times after the or"

        if len(self.data) == 0:
            assert not must_find, "Must compile down to at least one result"
            return RelaxedDictionary({})
        
        if len(self.data) == 1:
            return self.data[0]

        if allow_duplicates:
            return self.data[0]

        for item in self.data:
            print(json.dumps(item.get_base(), indent=4))

        assert False, "Should filter down to one item only to use this function"


def flatten_json(d: dict, delim: str) -> dict:
    """Takes in a nested dictionary and returns a flat dictionary.
    From: https://stackoverflow.com/a/28246154

    Args:
        d (dict): The dictionary to flatten
        delim (str): Delimiter to use for nested dictionaries.

    Returns:
        dict: The flat dictionary
    """
    val = {}
    for i in d.keys():
        if isinstance(d[i], dict):
            get = flatten_json(d[i], delim)
            for j in get.keys():
                val[i + delim + j] = get[j]
        else:
            val[i] = d[i]
    return val


def dict_to_csv(json_dict: List[dict], delim=".") -> str:
    """Flattens and converts a dictionary to a csv using the delimeter to show
    nested content.

    Args:
        json_dict (dict): Dataset to save to csv
        delim (str, optional): Delimiter to use for nested dictionaries.
                               Defaults to ".".

    Returns:
        str: The csv as a string
    """
    fields = {}
    for record in json_dict:
        record = flatten_json(record, delim)
        for key in record.keys():
            fields[key] = None
    
    f = StringIO()
    writer = csv.DictWriter(f, fieldnames=fields.keys())
    writer.writeheader()

    for record in json_dict:
        record = flatten_json(record, delim)
        writer.writerow(record)
    
    return f.getvalue().replace("\r", "")


def dict_diff(inserting_dict: dict, existing_dict: dict) -> dict:
    """Generates a dictionary containing the diff of two dictionaries.

    Args:
        inserting_dict (dict): The dictionary to keep if different
        existing_dict (dict): The dictionary to compare against.

    Returns:
        dict: The fields in the inserting_dict that are different to the
              existing_dict.
    """
    combined_dict = existing_dict | inserting_dict
    diff_dict = {}
    # Create diff dictionary
    for k, v in combined_dict.items():
        if k in existing_dict and existing_dict[k] == v:
            continue
        diff_dict[k] = v
    return diff_dict


def dict_to_url_query(d: dict) -> str:
    queries = []
    for key, value in d.items():
        value = str(value).replace(" ", "%20")
        queries.append(f"{key}={value}")
    return "&".join(queries)


def nested_get(dictionary: dict, *keys, default_value=None):
    """
    Will attempt to continue to getting values from nested dictionaries
    if the value doesn't exist then the default value is returned. If it
    finds that a key along the way points to something other than a
    dictionary, it will instead stop iteration and return that value.
    Pass as many keys as you desire.
    """
    if dictionary is None:
        return default_value
    
    for key in keys:
        if key not in dictionary:
            return default_value
        
        dictionary = dictionary[key]
        if not isinstance(dictionary, dict):
            break
    return dictionary


def arrayify_dict(d: dict, query: List[str], key_to_add: str):
    """Some APIs like to use dictionaries where they should be using a list.
    This let's me convert them to lists.
    """
    assert len(query) > 0, "Must have something to lookup"
    prior_lookup = query[:-1]
    final_key = query[-1]

    d: RelaxedDictionary = RelaxedDictionary(d)
    dict_should_be_list: dict = d.get(*query, default={})
    inserting_list = []
    for key, nest in dict_should_be_list.items():
        nest[key_to_add] = key
        inserting_list.append(nest)
    
    d.set(prior_lookup, final_key, inserting_list)
    return d


def safe_open_w(path: str, **kwargs):
    """Open "path" for writing, creating any parent directories as needed.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return open(path, "w", **kwargs)


def safe_open_wb(path: str, **kwargs):
    """Open "path" for writing, creating any parent directories as needed.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return open(path, "wb", **kwargs)


def cache_json(file_path: str, verbose=False):
    """Decorator to cache the result of the function as a json file.

    Args:
        file_name (str): The file to save to
    """
    def decorator(func_returning_dict: Callable[[], dict]):
        def wrapper(*args, **kwargs):
            contents = func_returning_dict(*args, **kwargs)

            if verbose:
                print("Saving json", file_path)
            try:
                with safe_open_w(file_path, encoding="utf-8") as f:
                    json.dump(contents, f, indent=4)
            except PermissionError as e:
                print("Ignoring", e)
            return contents
        return wrapper
    return decorator


def cache_csv(file_path: str, verbose=False):
    """Decorator to cache the result of the function as a csv. Flattens the
    dictionary first.

    Args:
        file_path (str): The file to save to
    """
    def decorator(func_returning_dict: Callable[[], dict]):
        def wrapper(*args, **kwargs):
            contents = func_returning_dict(*args, **kwargs)

            if verbose:
                print("Saving csv", file_path)
            with safe_open_w(file_path, encoding="utf-8") as f:
                f.write(dict_to_csv(contents))
            return contents
        return wrapper
    return decorator


def ip_strip_subnet(ip_with_subnet: str):
    return ip_with_subnet.split("/")[0]


def ip_in_subnet(ip_with_subnet: str, valid_prefixes: List[str] | str):
    if not isinstance(valid_prefixes, list):
        valid_prefixes = [valid_prefixes]
    
    ip_address = ipaddress.ip_address(ip_strip_subnet(ip_with_subnet))
    prefixes = [ipaddress.ip_network(p) for p in valid_prefixes]
    for prefix in prefixes:
        if ip_address in prefix:
            return True
    return False


def stacktrace_of(e: Exception):
    errors = io.StringIO()
    traceback.print_exc(file=errors)  # Instead of printing directly to stdout, the result can be further processed
    return str(errors.getvalue())


def __get_user():
    res: APIResponse = APIRequest("https://gorest.co.in/public/v2/users") \
        .set_method(Method.Get) \
        .execute()
        
    print(res.status_code())
    print(res.json_pretty())


def __create_user():
    res: APIResponse = APIRequest("https://gorest.co.in/public/v2/users") \
        .set_method(Method.Post) \
        .add_parameters({
            "name": "Gene Takovich",
            "gender": "male",
            "email": "notsaul@goodman.com",
            "status": "active"
        })\
        .set_content_type(ContentType.ApplicationJson) \
        .execute()
        
    print(res.status_code())
    print(res.json_pretty())


def main():
    # __get_user()
    __create_user()


if __name__ == "__main__":
    main()
