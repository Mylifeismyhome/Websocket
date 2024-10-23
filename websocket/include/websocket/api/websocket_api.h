#pragma once

#ifdef WEBSOCKET_SHARED
#if defined( _WIN32 ) && !defined( EFIX64 ) && !defined( EFI32 )
#ifdef WEBSOCKET_EXPORT
#define WEBSOCKET_API __declspec( dllexport )
#else
#define WEBSOCKET_API __declspec( dllimport )
#endif
#else
#define WEBSOCKET_API __attribute__( ( visibility( "default" ) ) )
#endif
#else
#define WEBSOCKET_API
#endif
