def build_ocr_artifact_key(document_route: str, doc_id: str) -> str:
    """
    Builder canónico para la llave del artifact OCR en S3.
    La ruta siempre será <document_route>/<docId>/ocr.json
    """
    if not document_route or not doc_id:
        raise ValueError("document_route and doc_id are mandatory to build the artifact key")
    
    return f"{document_route}/{doc_id}/ocr.json"
