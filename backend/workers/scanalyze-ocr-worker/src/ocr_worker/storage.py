def build_document_prefix(customer_id: str, deployment_id: str, doc_id: str) -> str:
    if not customer_id or not deployment_id or not doc_id:
        raise ValueError("customer_id, deployment_id and doc_id are mandatory")
    if any("#" in value or "/" in value for value in (customer_id, deployment_id, doc_id)):
        raise ValueError("ownership identifiers cannot contain path delimiters")
    return (
        f"customers/{customer_id}/deployments/{deployment_id}/"
        f"documents/{doc_id}/"
    )


def build_ocr_artifact_key(customer_id: str, deployment_id: str, doc_id: str) -> str:
    """Build the ownership-bound OCR artifact key for one document."""

    return f"{build_document_prefix(customer_id, deployment_id, doc_id)}ocr.json"
