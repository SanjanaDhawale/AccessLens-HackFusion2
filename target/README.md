# ConnectedCar demo target

Implement a local-only FastAPI API with synthetic users and vehicle records. Required identities: Anonymous, Alice (owner), Bob (different owner), Technician, Admin.

Plant repeatable read BOLA, write BOLA, BFLA, missing-authentication, and excessive-data-exposure cases. Include secure control endpoints and vulnerable/fixed modes. Use disposable test records and a deterministic reset endpoint. Never connect to real vehicles or external systems.
