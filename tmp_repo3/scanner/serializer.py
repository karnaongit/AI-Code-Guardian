from dataclasses import asdict, is_dataclass


class ResponseSerializer:

    @staticmethod
    def serialize(obj):

        if obj is None:
            return None

        if is_dataclass(obj):
            return asdict(obj)

        if isinstance(obj, list):
            return [
                ResponseSerializer.serialize(item)
                for item in obj
            ]

        if isinstance(obj, dict):
            return {
                key: ResponseSerializer.serialize(value)
                for key, value in obj.items()
            }

        return obj