class ResourceException(Exception):
    pass


class ResourceNotFound(ResourceException):
    pass


class ResourceDeleted(ResourceException):
    pass


class SecretShareMissing(ResourceException):
    pass


class MetadataMissing(ResourceException):
    pass


class MetadataKeyNotShared(ResourceException):
    pass


class DecryptError(ResourceException):
    pass


class IntegrityError(ResourceException):
    pass


class SchemaValidationError(ResourceException):
    pass


class InvalidResourceId(ResourceException):
    pass
