"""Unit tests for the OpenAPI 3.1 spec emitter."""

from std.testing import assert_equal

from flare.http import Request, Response, Router, ok
from flare.openapi import (
    OpenApiOperation,
    OpenApiParameter,
    OpenApiPath,
    OpenApiResponse,
    OpenApiSpec,
    emit_openapi_json,
    spec_from_router,
)


def _h(req: Request) raises -> Response:
    return ok("x")


def test_minimal_spec_emits_canonical_json() raises:
    """The simplest OpenAPI document has a byte-exact representation."""
    var spec = OpenApiSpec.new(String("Test API"), String("1.0.0"))
    assert_equal(
        emit_openapi_json(spec),
        (
            '{"openapi":"3.1.0","info":{"title":"Test'
            ' API","version":"1.0.0"},"paths":{}}'
        ),
    )


def test_path_with_get_operation() raises:
    """A GET operation emits parameters, response content, and fallback."""
    var spec = OpenApiSpec.new(String("Users API"), String("2.0"))
    var params = List[OpenApiParameter]()
    params.append(
        OpenApiParameter(
            name=String("limit"),
            location=String("query"),
            required=False,
            schema_type=String("integer"),
        )
    )
    var responses = List[OpenApiResponse]()
    responses.append(
        OpenApiResponse(
            status=String("200"),
            description=String("List of users"),
            content_type=String("application/json"),
        )
    )
    responses.append(
        OpenApiResponse(
            status=String("default"),
            description=String("Unexpected error"),
            content_type=String(""),
        )
    )
    var operation = OpenApiOperation(
        method=String("get"),
        summary=String("List users"),
        operation_id=String("listUsers"),
        parameters=params^,
        responses=responses^,
    )
    var operations = List[OpenApiOperation]()
    operations.append(operation^)
    spec.paths.append(
        OpenApiPath(template=String("/users"), operations=operations^)
    )
    assert_equal(
        emit_openapi_json(spec),
        (
            '{"openapi":"3.1.0","info":{"title":"Users'
            ' API","version":"2.0"},"paths":{"/users":{"get":{"operationId":"listUsers","summary":"List'
            ' users","parameters":[{"in":"query","name":"limit","required":false,"schema":{"type":"integer"}}],"responses":{"200":{"description":"List'
            ' of users","content":{"application/json":{"schema":{"type":"object"}}}},"default":{"description":"Unexpected'
            ' error"}}}}}}'
        ),
    )


def test_json_escaping_preserves_special_chars() raises:
    """Quotes, backslashes, and newlines emit their JSON escape forms."""
    var spec = OpenApiSpec.new(
        String('API with "quotes" and \\backslashes\\'),
        String("1.0"),
    )
    spec.info.description = String("Line 1\nLine 2")
    assert_equal(
        emit_openapi_json(spec),
        (
            '{"openapi":"3.1.0","info":{"title":"API with \\"quotes\\" and'
            ' \\\\backslashes\\\\","version":"1.0","description":"Line 1\\nLine'
            ' 2"},"paths":{}}'
        ),
    )


def test_emitter_is_deterministic() raises:
    """Equivalent specs emit byte-identical documents."""
    var first = OpenApiSpec.new(String("API"), String("1.0"))
    var second = OpenApiSpec.new(String("API"), String("1.0"))
    assert_equal(emit_openapi_json(first), emit_openapi_json(second))


def test_spec_from_router_paths_and_params() raises:
    """Router derivation emits merged methods and templated parameters."""
    var router = Router()
    router.get("/users", _h)
    router.post("/users", _h)
    router.get("/users/:id", _h)
    router.get("/files/*", _h)

    var spec = spec_from_router(router, String("Derived"), String("9.9"))
    assert_equal(
        emit_openapi_json(spec),
        (
            '{"openapi":"3.1.0","info":{"title":"Derived","version":"9.9"},'
            '"paths":{"/users":{"get":{"operationId":"get_users","responses":{'
            '"200":{"description":"OK"}}},"post":{"operationId":"post_users",'
            '"responses":{"200":{"description":"OK"}}}},"/users/{id}":{"get":{'
            '"operationId":"get_users__id_","parameters":[{"in":"path","name":"id",'
            '"required":true,"schema":{"type":"string"}}],"responses":{"200":{'
            '"description":"OK"}}}},"/files/{path}":{"get":{"operationId":'
            '"get_files__path_","responses":{"200":{"description":"OK"}}}}}}'
        ),
    )


def test_spec_from_router_is_deterministic() raises:
    var first = Router()
    first.get("/a", _h)
    first.post("/a", _h)
    var second = Router()
    second.get("/a", _h)
    second.post("/a", _h)
    assert_equal(
        emit_openapi_json(spec_from_router(first, String("A"), String("1"))),
        emit_openapi_json(spec_from_router(second, String("A"), String("1"))),
    )


def main() raises:
    test_minimal_spec_emits_canonical_json()
    test_path_with_get_operation()
    test_json_escaping_preserves_special_chars()
    test_emitter_is_deterministic()
    test_spec_from_router_paths_and_params()
    test_spec_from_router_is_deterministic()
    print("test_openapi: OK")
