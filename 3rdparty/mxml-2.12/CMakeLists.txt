set(mxml_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR} PARENT_SCOPE)
set(mxml_LIBRARIES mxml PARENT_SCOPE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_definitions(-D_GNU_SOURCE)
add_library(mxml STATIC
    mxml-attr.c
	mxml-entity.c
	mxml-file.c
	mxml-get.c
	mxml-index.c
	mxml-node.c
	mxml-private.c
	mxml-search.c
	mxml-set.c
	mxml-string.c
    )
