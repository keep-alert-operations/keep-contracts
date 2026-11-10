from keep.ingestion.native import canonical


def received_key(tenant, application, key):
    return canonical([str(tenant), application, key])
