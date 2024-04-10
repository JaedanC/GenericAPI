from __future__ import annotations
import json
from netbox_python.baseapi import APIResource
from netbox_python.exceptions import NetBoxException
from typing import List, Dict
import sqlite3
import datetime


class NetBoxLog:
    """This class will handle hands-off operation by logging any information
    into a sqllite database.
    """
    def __init__(self, sqllite_connection: sqlite3.Connection):
        self.con: sqlite3.Connection = sqllite_connection
        cur = self.con.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS info
            (
                time TIMESTAMP,
                message TEXT NOT NULL
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS post
            (
                time TIMESTAMP,
                endpoint TEXT NOT NULL,
                data TEXT NOT NULL
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS patch
            (
                time TIMESTAMP,
                endpoint TEXT NOT NULL,
                id TEXT NOT NULL,
                data TEXT NOT NULL
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS deletes
            (
                time TIMESTAMP,
                endpoint TEXT NOT NULL,
                data TEXT NOT NULL
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS errors
            (
                time TIMESTAMP,
                endpoint TEXT NOT NULL,
                message TEXT NOT NULL
            );
        """)
    
    def info(self, message: str):
        cur = self.con.cursor()
        cur.execute("""
            INSERT INTO info VALUES (?, ?)""",
            (datetime.datetime.now(), message)
        )
        self.con.commit()

    def post(self, endpoint: APIResource, data_inserted: dict):
        cur = self.con.cursor()
        cur.execute("""
            INSERT INTO post VALUES (?, ?, ?)""",
            (datetime.datetime.now(), endpoint.path, json.dumps(data_inserted))
        )
        self.con.commit()

    def patch(self, endpoint: APIResource, id_: str, data_patched: dict):
        cur = self.con.cursor()
        cur.execute("""
            INSERT INTO patch VALUES (?, ?, ?, ?)""",
            (datetime.datetime.now(), endpoint.path, str(id_), json.dumps(data_patched))
        )
        self.con.commit()

    def delete(self, endpoint: APIResource, data_deleted: dict):
        cur = self.con.cursor()
        cur.execute("""
            INSERT INTO deletes VALUES (?, ?, ?)""",
            (datetime.datetime.now(), endpoint.path, json.dumps(data_deleted))
        )
        self.con.commit()

    def error(self, endpoint: APIResource, error_message: str):
        cur = self.con.cursor()
        cur.execute("""
            INSERT INTO errors VALUES (?, ?, ?)""",
            (datetime.datetime.now(), endpoint.path if endpoint is not None else "", error_message)
        )
        self.con.commit()
    

class NetBoxDeleteOrganiser:
    def __init__(self, logger: NetBoxLog):
        self.deletes: Dict[APIResource, List[int]] = {}
        self.order_to_delete = None
        self.logger = logger
    
    def add_delete(
            self,
            endpoint: APIResource,
            keys_to_delete: List[int]
        ):
        assert isinstance(endpoint, APIResource)
        if endpoint in self.deletes:
            self.deletes[endpoint] += keys_to_delete
        else:
            self.deletes[endpoint] = keys_to_delete
    
    def delete_in_order(self, *endpoints: List[APIResource], skip_prompt=False):
        assert len(set(endpoints)) == len(self.deletes)
        for endpoint in endpoints:
            assert endpoint in self.deletes
        
        for endpoint in endpoints:
            keys_to_delete = self.deletes[endpoint]
            for deleting_key in keys_to_delete:
                print(f"Deleting {deleting_key} in Netbox.")
                are_you_sure_deleting = endpoint.get(deleting_key).data
                print(json.dumps(are_you_sure_deleting, indent=4))
                try:
                    if not skip_prompt:
                        input("Press enter to delete the object or CTRL+C to cancel.")
                    endpoint.delete(deleting_key)
                    self.logger.delete(endpoint, are_you_sure_deleting)
                except NetBoxException as e:
                    self.logger.error(endpoint, str(e))
                    raise e
                except KeyboardInterrupt:
                    pass


class NetBoxChange:
    def __init__(self, logger: NetBoxLog):
        self.patch_keys = []
        self.logger = logger
    
    def insert(self, endpoint: APIResource, data: dict, patch_key: int | None, get=False):
        # POST
        if patch_key is None:
            print("Creating new")
            print(json.dumps(data, indent=4))
            try:
                results = endpoint.create(**data).data
                self.logger.post(endpoint, data)
            except NetBoxException as e:
                self.logger.error(endpoint, str(e))
                raise e

            print("Response")
            print(json.dumps(results, indent=4))
            return results

        self.patch_keys.append(patch_key)

        # Return existing
        if len(data) == 0:
            if get:
                return endpoint.get(patch_key).data
            return

        # PATCH
        print("Patching {}".format(endpoint))
        print("Modifying {}".format(patch_key))
        print(json.dumps(data, indent=4))
        try:
            results = endpoint.update(patch_key, **data).data
            self.logger.patch(endpoint, patch_key, data)
        except NetBoxException as e:
            self.logger.error(endpoint, str(e))
            raise e
        
        print("Response")
        print(json.dumps(results, indent=4))
        return results
    

    def mark_as_inserted(self, patch_key: int):
        self.patch_keys.append(patch_key)


    def get_keys_inserted(self):
        return self.patch_keys

    
    def get_keys_not_inserted_from(
            self,
            keys_that_could_be_deleted: List[int],
        ):
        skip_keys = set(self.patch_keys)
        keys_to_delete_set = set(keys_that_could_be_deleted)
        to_delete_ids = keys_to_delete_set.difference(skip_keys)
        return list(to_delete_ids)


    def delete_not_inserted_from(
            self,
            endpoint: APIResource,
            keys_that_could_be_deleted: List[int],
            unsafe_skip=False
        ):
        """Delete any existing objects that are not found in the Change.
        It is extremely important that the keys_that_could_be_deleted does not
        contain information for objects that we didn't try to insert. Otherwise
        we will wipe the floor with deletes.

        Returns the list of ids of objects that were deleted.
        """
        return self.delete_keys(
            endpoint,
            self.get_keys_not_inserted_from(keys_that_could_be_deleted),
            unsafe_skip
        )
    

    def delete_keys(
            self, 
            endpoint: APIResource,
            keys_to_delete: List[int],
            unsafe_skip=False
        ):
        for deleting_key in keys_to_delete:
            print(f"Deleting {deleting_key} in Netbox.")
            are_you_sure_deleting = endpoint.get(deleting_key).data
            print(json.dumps(are_you_sure_deleting, indent=4))
            try:
                if not unsafe_skip:
                    input("Press enter to delete the object or CTRL+C to cancel.")
                endpoint.delete(deleting_key)
                self.logger.delete(endpoint, are_you_sure_deleting)
            except NetBoxException as e:
                self.logger.error(endpoint, str(e))
                raise e
            except KeyboardInterrupt:
                pass
        return keys_to_delete


def get_tag_slugs(tags: List[dict]) -> List[dict]:
    if tags is None:
        return []
    return [{"slug": t["slug"]} for t in tags]
    

def add_tag(tags: List[dict], tag_to_add: dict) -> List[dict]:
    if tags is None:
        return [tag_to_add]
    tag_slugs = get_tag_slugs(tags)
    for existing_tag in tag_slugs:
        if existing_tag["slug"] == tag_to_add["slug"]:
            return tag_slugs
    tag_slugs.append(tag_to_add)
    return tag_slugs


def is_ipv4(ip_address: str):
    if ip_address is None:
        return False
    return ":" not in ip_address


def is_ipv6(ip_address: str):
    if ip_address is None:
        return False
    return ":" in ip_address

