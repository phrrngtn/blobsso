# This file is included by DuckDB's build system. It specifies which extension to load

# Extension from this repo
duckdb_extension_load(blobsso
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}
)

# NOTE: httpfs is NOT compiled in. It's out-of-tree, and our 'sso' provider only
# needs the s3 secret *type* it registers (plus, later, its core HTTPUtil) — both
# available at runtime. The tests pull the prebuilt, signed httpfs via INSTALL/LOAD.