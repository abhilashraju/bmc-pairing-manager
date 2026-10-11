/**
 * @file sdbus_calls.hpp
 * @brief Coroutine-based D-Bus API wrappers for asynchronous operations
 *
 * This file provides awaitable wrappers around sdbusplus async operations,
 * enabling the use of C++20 coroutines (co_await) for D-Bus method calls,
 * property access, and object mapper queries.
 *
 * ## Key Features
 * - Coroutine-based async D-Bus operations using co_await
 * - Type-safe property getters and setters
 * - Object mapper integration for service discovery
 * - Managed object and introspection support
 *
 * ## Error Handling
 * All functions return AwaitableResult<T...> which unpacks to:
 *   auto [ec, value] = co_await function(...);
 * Where:
 * - ec: boost::system::error_code indicating success/failure
 * - value: The requested data (only valid if !ec)
 *
 * Always check the error_code before using returned values:
 *   if (ec) {
 *       // Handle error
 *       return;
 *   }
 *   // Use value safely
 *
 * ## Usage Example
 * @code
 * AwaitableResult<std::string> getSystemName(
 *     sdbusplus::asio::connection& bus) {
 *     auto [ec, name] = co_await getProperty<std::string>(
 *         bus, "xyz.openbmc_project.State.Host",
 *         "/xyz/openbmc_project/state/host0",
 *         "xyz.openbmc_project.State.Host", "CurrentHostState");
 *     if (ec) {
 *         LOG_ERROR("Failed to get host state: {}", ec.message());
 *         co_return ReturnTuple<std::string>{ec, ""};
 *     }
 *     co_return ReturnTuple<std::string>{ec, name};
 * }
 * @endcode
 */
#pragma once
#include "logger.hpp"
#include "make_awaitable.hpp"

#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <sdbusplus/asio/property.hpp>
#include <sdbusplus/asio/sd_event.hpp>
#include <sdbusplus/bus.hpp>
#include <sdbusplus/exception.hpp>
#include <sdbusplus/server.hpp>
#include <sdbusplus/timer.hpp>

// ---------------------------------------------------------------------------
// sdbusplus version compatibility shims
//
// Older sdbusplus exposed:
//   sdbusplus::message::object_path
//   sdbusplus::bus::match::match
//
// Newer sdbusplus (post-2024) moved these to the top-level namespace:
//   sdbusplus::object_path
//   sdbusplus::match
//
// meson.build probes for the new API and sets -DSDBUSPLUS_NEW_API when found.
// ---------------------------------------------------------------------------
namespace sdbuscompat
{
#ifdef SDBUSPLUS_NEW_API
using object_path = ::sdbusplus::object_path;
using match_t = ::sdbusplus::match;
#else
using object_path = ::sdbusplus::message::object_path;
using match_t = ::sdbusplus::bus::match::match;
#endif
} // namespace sdbuscompat

namespace NSNAME
{
// Common D-Bus service and interface names
constexpr auto objectMapperService = "xyz.openbmc_project.ObjectMapper";
constexpr auto objectMapperPath = "/xyz/openbmc_project/object_mapper";
constexpr auto objectMapperInterface = "xyz.openbmc_project.ObjectMapper";
constexpr auto dbusPropertiesInterface = "org.freedesktop.DBus.Properties";
constexpr auto dbusObjectManagerInterface =
    "org.freedesktop.DBus.ObjectManager";
constexpr auto dbusIntrospectableInterface =
    "org.freedesktop.DBus.Introspectable";
constexpr auto associationInterface = "xyz.openbmc_project.Association";

/** @brief Map of property names to their variant values */
using PropertyMap =
    std::map<std::string, std::variant<bool, int32_t, std::string, uint32_t>>;

/** @brief Map of interface names to their property maps */
using InterfaceMap = std::map<std::string, PropertyMap>;

/**
 * @brief Awaitable wrapper for D-Bus method calls with return values
 *
 * @tparam RetTypes Return value types from the D-Bus method
 * @tparam InputArgs Input argument types for the D-Bus method
 * @param bus D-Bus connection object
 * @param service D-Bus service name (e.g., "xyz.openbmc_project.State.Host")
 * @param objpath D-Bus object path (e.g., "/xyz/openbmc_project/state/host0")
 * @param interf D-Bus interface name
 * @param method D-Bus method name to call
 * @param a Input arguments to pass to the method
 * @return AwaitableResult<RetTypes...> Tuple of [error_code, return_values...]
 *
 * @note Always check error_code before using return values
 *
 * Example:
 * @code
 * auto [ec, state, id] = co_await awaitable_dbus_method_call<std::string, int>(
 *     bus, "com.example.Service", "/com/example/Object",
 *     "com.example.Interface", "GetStateAndId");
 * if (!ec) {
 *     // Use state and id
 * }
 * @endcode
 */
// NOLINTBEGIN(cppcoreguidelines-avoid-reference-coroutine-parameters)
template <typename... RetTypes, typename... InputArgs>
inline auto awaitable_dbus_method_call(
    sdbusplus::asio::connection& bus, std::string service, std::string objpath,
    std::string interf, std::string method, const InputArgs&... a)
    -> AwaitableResult<RetTypes...>
{
    auto h = make_awaitable_handler<RetTypes...>([&](auto promise) {
        bus.async_method_call(
            [promise = std::move(promise)](boost::system::error_code ec,
                                           RetTypes... values) mutable {
                promise.setValues(ec, std::move(values)...);
            },
            service, objpath, interf, method, a...);
    });
    co_return co_await h();
}

/**
 * @brief Awaitable wrapper for D-Bus method calls with no return value
 *
 * Specialized version for void return type - returns only error_code.
 *
 * @note This function internally calls the generic awaitable_dbus_method_call
 * with sdbusplus::message_t as the return type. The message_t is used because
 * D-Bus method replies always contain a message object, even for void methods.
 * This wrapper extracts only the error_code and discards the message, providing
 * a cleaner interface for callers who don't need the raw message.
 *
 * @note Use this function when calling D-Bus methods that don't return any data
 * (void methods). Use the generic awaitable_dbus_method_call when you need to
 * retrieve return values from the method.
 *
 * @tparam InputArgs Input argument types for the D-Bus method
 * @param bus D-Bus connection object
 * @param service D-Bus service name
 * @param objpath D-Bus object path
 * @param interf D-Bus interface name
 * @param method D-Bus method name to call
 * @param a Input arguments to pass to the method
 * @return AwaitableResult<boost::system::error_code> Error code indicating
 * success/failure
 *
 * Example:
 * @code
 * auto [ec] = co_await awaitable_dbus_method_call_void(
 *     bus, "com.example.Service", "/com/example/Object",
 *     "com.example.Interface", "Reset");
 * if (ec) {
 *     LOG_ERROR("Reset failed: {}", ec.message());
 * }
 * @endcode
 */
template <typename... InputArgs>
inline AwaitableResult<boost::system::error_code>
    awaitable_dbus_method_call_void(sdbusplus::asio::connection& bus,
                                    std::string service, std::string objpath,
                                    std::string interf, std::string method,
                                    const InputArgs&... a)
{
    auto [ec, msg] = co_await awaitable_dbus_method_call<sdbusplus::message_t>(
        bus, service, objpath, interf, method, a...);
    co_return ReturnTuple<boost::system::error_code>{ec};
}

/**
 * @brief Get a D-Bus property value
 *
 * Retrieves a single property value from a D-Bus object using the standard
 * org.freedesktop.DBus.Properties.Get method.
 *
 * @tparam Type Expected type of the property value
 * @param bus D-Bus connection object
 * @param service D-Bus service name owning the object
 * @param objpath D-Bus object path
 * @param interf D-Bus interface containing the property
 * @param property Property name to retrieve
 * @return AwaitableResult<Type> Tuple of [error_code, property_value]
 *
 * @note Returns default-constructed Type if error occurs or type mismatch
 *
 * Example:
 * @code
 * auto [ec, enabled] = co_await getProperty<bool>(
 *     bus, "xyz.openbmc_project.Settings",
 *     "/xyz/openbmc_project/network/eth0",
 *     "xyz.openbmc_project.Network.EthernetInterface", "NICEnabled");
 * if (!ec && enabled) {
 *     // Interface is enabled
 * }
 * @endcode
 */
template <typename Type>
inline AwaitableResult<Type> getProperty(
    sdbusplus::asio::connection& bus, std::string service, std::string objpath,
    std::string interf, std::string property)
{
    auto [ec, value] =
        co_await awaitable_dbus_method_call<std::variant<std::monostate, Type>>(
            bus, service, objpath, dbusPropertiesInterface, "Get", interf,
            property);
    if (ec)
    {
        co_return ReturnTuple<Type>{ec, Type{}};
    }
    if (!std::holds_alternative<Type>(value))
    {
        LOG_ERROR("Error getting property: Type miss match");
        ec = boost::asio::error::invalid_argument;
        co_return ReturnTuple<Type>{ec, Type{}};
    }
    co_return ReturnTuple<Type>{ec, std::get<Type>(value)};
}

/**
 * @brief Set a D-Bus property value
 *
 * Sets a single property value on a D-Bus object using the standard
 * org.freedesktop.DBus.Properties.Set method.
 *
 * @tparam InputArgs Type of the property value to set
 * @param bus D-Bus connection object
 * @param service D-Bus service name owning the object
 * @param objpath D-Bus object path
 * @param interf D-Bus interface containing the property
 * @param property Property name to set
 * @param value New value for the property
 * @return AwaitableResult<boost::system::error_code> Error code indicating
 * success/failure
 *
 * Example:
 * @code
 * auto [ec] = co_await setProperty(
 *     bus, "xyz.openbmc_project.Settings",
 *     "/xyz/openbmc_project/network/eth0",
 *     "xyz.openbmc_project.Network.EthernetInterface", "NICEnabled", true);
 * if (ec) {
 *     LOG_ERROR("Failed to enable interface: {}", ec.message());
 * }
 * @endcode
 */
template <typename InputArgs>
inline AwaitableResult<boost::system::error_code> setProperty(
    sdbusplus::asio::connection& bus, std::string service, std::string objpath,
    std::string interf, std::string property, const InputArgs& value)
{
    auto h =
        make_awaitable_handler<boost::system::error_code>([&](auto promise) {
            sdbusplus::asio::setProperty(
                bus, service, objpath, interf, property, value,
                [promise = std::move(promise)](
                    boost::system::error_code ec) mutable {
                    promise.setValues(ec);
                });
        });
    co_return co_await h();
}

/**
 * @brief Get all properties of a D-Bus interface
 *
 * Retrieves all properties from a D-Bus interface using the standard
 * org.freedesktop.DBus.Properties.GetAll method.
 *
 * @param bus D-Bus connection object
 * @param service D-Bus service name owning the object
 * @param path D-Bus object path
 * @param interface D-Bus interface name
 * @return AwaitableResult<PropertyMap> Tuple of [error_code, property_map]
 *         where property_map is std::map<string, variant<bool, int32_t, string,
 * uint32_t>>
 *
 * Example:
 * @code
 * auto [ec, props] = co_await getAllProperties(
 *     bus, "xyz.openbmc_project.Network",
 *     "/xyz/openbmc_project/network/eth0",
 *     "xyz.openbmc_project.Network.EthernetInterface");
 * if (!ec) {
 *     // Access properties from props map
 * }
 * @endcode
 */
inline AwaitableResult<PropertyMap> getAllProperties(
    sdbusplus::asio::connection& bus, std::string service, std::string path,
    std::string interface)
{
    co_return co_await awaitable_dbus_method_call<PropertyMap>(
        bus, service, path, dbusPropertiesInterface, "GetAll", interface);
}

/**
 * @brief Generic helper for D-Bus ObjectMapper method calls
 *
 * Reduces code duplication by providing a single implementation for all
 * ObjectMapper method calls that follow the same pattern.
 *
 * @tparam ReturnType Expected return type from the D-Bus method
 * @tparam Args Variadic template for method arguments
 * @param bus D-Bus connection object
 * @param method ObjectMapper method name to call
 * @param args Arguments to pass to the method
 * @return AwaitableResult<ReturnType> Tuple of [error_code, result]
 */
template <typename ReturnType, typename... Args>
inline AwaitableResult<ReturnType> callObjectMapperMethod(
    sdbusplus::asio::connection& bus, std::string method, const Args&... args)
{
    co_return co_await awaitable_dbus_method_call<ReturnType>(
        bus, objectMapperService, objectMapperPath, objectMapperInterface,
        method, args...);
}

// Canonical type for GetSubTree responses.
// D-Bus wire type: a{sa{sas}}
//   object-path → service-name → array of interfaces
using SubTreeMap =
    std::map<std::string, std::map<std::string, std::vector<std::string>>>;

/**
 * @brief Query D-Bus object mapper for a subtree of objects
 *
 * Retrieves objects and their interfaces from the object mapper within a
 * specified path and depth.
 *
 * @tparam SubTreeMapType Expected return type (typically std::map<std::string,
 * InterfaceMap>)
 * @param bus D-Bus connection object
 * @param path Root path to search from
 * @param depth Search depth (0 = only path, -1 = unlimited)
 * @param interfaces Optional filter for specific interfaces
 * @return AwaitableResult<SubTreeMapType> Tuple of [error_code, subtree_map]
 *
 * Example:
 * @code
 * using SubTree = std::map<std::string, std::map<std::string,
 * std::vector<std::string>>>; auto [ec, subtree] = co_await
 * getSubTree<SubTree>( bus, "/xyz/openbmc_project/inventory", 0,
 *     {"xyz.openbmc_project.Inventory.Item"});
 * @endcode
 */
template <typename SubTreeMapType>
inline AwaitableResult<SubTreeMapType> getSubTree(
    sdbusplus::asio::connection& bus, const std::string& path, int depth,
    const std::vector<std::string>& interfaces = {})
{
    return callObjectMapperMethod<SubTreeMapType>(bus, "GetSubTree", path,
                                                  depth, interfaces);
}

/// Convenience overload — deduces SubTreeMap as the return type.
inline AwaitableResult<SubTreeMap> getSubTree(
    sdbusplus::asio::connection& bus, const std::string& path, int depth,
    const std::vector<std::string>& interfaces = {})
{
    return getSubTree<SubTreeMap>(bus, path, depth, interfaces);
}

/**
 * @brief Get D-Bus services providing a specific object
 *
 * Queries the object mapper for all services that provide the specified
 * object path and interfaces.
 *
 * @tparam DictType Expected return type (typically std::map<std::string,
 * std::vector<std::string>>)
 * @param bus D-Bus connection object
 * @param path D-Bus object path to query
 * @param interfaces Optional filter for specific interfaces
 * @return AwaitableResult<DictType> Tuple of [error_code, service_map]
 *         where service_map maps service names to their provided interfaces
 */
template <typename DictType>
inline AwaitableResult<DictType> getObjects(
    sdbusplus::asio::connection& bus, const std::string& path,
    const std::vector<std::string>& interfaces = {})
{
    return callObjectMapperMethod<DictType>(bus, "GetObject", path, interfaces);
}
/**
 * @brief Get object paths from a subtree query
 *
 * Similar to getSubTree but returns only the object paths without interface
 * details.
 *
 * @tparam DictType Expected return type (typically std::vector<std::string>)
 * @param bus D-Bus connection object
 * @param path Root path to search from
 * @param depth Search depth (0 = only path, -1 = unlimited)
 * @param interfaces Optional filter for specific interfaces
 * @return AwaitableResult<DictType> Tuple of [error_code, paths_list]
 */
template <typename DictType>
inline AwaitableResult<DictType> getSubTreePaths(
    sdbusplus::asio::connection& bus, const std::string& path, int depth,
    const std::vector<std::string>& interfaces = {})
{
    return callObjectMapperMethod<DictType>(bus, "GetSubTreePaths", path, depth,
                                            interfaces);
}
/**
 * @brief Get subtree of objects associated with a specific path
 *
 * Queries for objects that have an association relationship with the specified
 * path.
 *
 * @tparam DictType Expected return type
 * @param bus D-Bus connection object
 * @param associatedPath Path to find associations for
 * @param path Root path to search from
 * @param depth Search depth
 * @param interfaces Optional filter for specific interfaces
 * @return AwaitableResult<DictType> Tuple of [error_code, associated_subtree]
 */
template <typename DictType>
inline AwaitableResult<DictType> getAssociatedSubTree(
    sdbusplus::asio::connection& bus,
    const sdbuscompat::object_path& associatedPath,
    const sdbuscompat::object_path& path, int depth,
    const std::vector<std::string>& interfaces = {})
{
    return callObjectMapperMethod<DictType>(
        bus, "GetAssociatedSubTree", associatedPath, path, depth, interfaces);
}

/**
 * @brief Get paths of objects associated with a specific path
 *
 * Similar to getAssociatedSubTree but returns only paths without interface
 * details.
 *
 * @tparam DictType Expected return type
 * @param bus D-Bus connection object
 * @param associatedPath Path to find associations for
 * @param path Root path to search from
 * @param depth Search depth
 * @param interfaces Optional filter for specific interfaces
 * @return AwaitableResult<DictType> Tuple of [error_code, associated_paths]
 */
template <typename DictType>
inline AwaitableResult<DictType> getAssociatedSubTreePaths(
    sdbusplus::asio::connection& bus,
    const sdbuscompat::object_path& associatedPath,
    const sdbuscompat::object_path& path, int32_t depth,
    const std::vector<std::string>& interfaces = {})
{
    return callObjectMapperMethod<DictType>(
        bus, "GetAssociatedSubTreePaths", associatedPath, path, depth,
        interfaces);
}

/**
 * @brief Get associated subtree filtered by ID
 *
 * Queries for objects associated with a specific ID through association
 * interfaces.
 *
 * @tparam DictType Expected return type
 * @param bus D-Bus connection object
 * @param id Identifier to search for
 * @param path Root path to search from
 * @param subtreeInterfaces Interfaces to search in the subtree
 * @param association Association type to follow
 * @param endpointInterfaces Interfaces required at association endpoints
 * @return AwaitableResult<DictType> Tuple of [error_code, associated_subtree]
 */
template <typename DictType>
inline AwaitableResult<DictType> getAssociatedSubTreeById(
    sdbusplus::asio::connection& bus, std::string id, std::string path,
    std::span<const std::string_view> subtreeInterfaces,
    std::string_view association,
    std::vector<std::string> endpointInterfaces = {})
{
    co_return co_await awaitable_dbus_method_call<DictType>(
        bus, objectMapperService, objectMapperPath, objectMapperInterface,
        "GetAssociatedSubTreeById", id, path, subtreeInterfaces, association,
        endpointInterfaces);
}

/**
 * @brief Get associated subtree paths filtered by ID
 *
 * Similar to getAssociatedSubTreeById but returns only paths.
 *
 * @tparam DictType Expected return type
 * @param bus D-Bus connection object
 * @param id Identifier to search for
 * @param path Root path to search from
 * @param subtreeInterfaces Interfaces to search in the subtree
 * @param association Association type to follow
 * @param endpointInterfaces Interfaces required at association endpoints
 * @return AwaitableResult<DictType> Tuple of [error_code, associated_paths]
 */
template <typename DictType>
inline AwaitableResult<DictType> getAssociatedSubTreePathsById(
    sdbusplus::asio::connection& bus, std::string id, std::string path,
    std::span<const std::string_view> subtreeInterfaces,
    std::string_view association, std::vector<std::string> endpointInterfaces)
{
    co_return co_await awaitable_dbus_method_call<DictType>(
        bus, objectMapperService, objectMapperPath, objectMapperInterface,
        "GetAssociatedSubTreePathsById", id, path, subtreeInterfaces,
        association, endpointInterfaces);
}

/**
 * @brief Get D-Bus object information from object mapper
 *
 * Queries the object mapper for services providing a specific object.
 *
 * @tparam DictType Expected return type
 * @param bus D-Bus connection object
 * @param path D-Bus object path
 * @param interfaces Optional filter for specific interfaces
 * @return AwaitableResult<DictType> Tuple of [error_code, object_info]
 */
template <typename DictType>
inline AwaitableResult<DictType> getDbusObject(
    sdbusplus::asio::connection& bus, std::string path,
    std::vector<std::string> interfaces = {})
{
    co_return co_await awaitable_dbus_method_call<DictType>(
        bus, objectMapperService, objectMapperPath, objectMapperInterface,
        "GetObject", path, interfaces);
}

/**
 * @brief Get association endpoints for a D-Bus object
 *
 * Retrieves the "endpoints" property from an association interface.
 *
 * @tparam DictType Expected return type (typically std::vector<std::string>)
 * @param bus D-Bus connection object
 * @param path D-Bus association object path
 * @return AwaitableResult<DictType> Tuple of [error_code, endpoints_list]
 */
template <typename DictType>
inline AwaitableResult<DictType> getAssociationEndPoints(
    sdbusplus::asio::connection& bus, std::string path)
{
    co_return co_await getProperty<DictType>(bus, objectMapperService, path,
                                             associationInterface, "endpoints");
}

/**
 * @brief Get all managed objects from a D-Bus service
 *
 * Retrieves all objects managed by a service using the ObjectManager interface.
 *
 * @tparam DictType Expected return type (typically std::map<object_path,
 * InterfaceMap>)
 * @param bus D-Bus connection object
 * @param service D-Bus service name
 * @param path D-Bus object manager path
 * @return AwaitableResult<DictType> Tuple of [error_code, managed_objects_map]
 *
 * Example:
 * @code
 * using ManagedObjects = std::map<sdbuscompat::object_path,
 * InterfaceMap>; auto [ec, objects] = co_await
 * getManagedObjects<ManagedObjects>( bus,
 * "xyz.openbmc_project.Inventory.Manager",
 *     "/xyz/openbmc_project/inventory");
 * @endcode
 */
template <typename DictType>
inline AwaitableResult<DictType> getManagedObjects(
    sdbusplus::asio::connection& bus, std::string service,
    sdbuscompat::object_path path)
{
    co_return co_await awaitable_dbus_method_call<DictType>(
        bus, service, path, dbusObjectManagerInterface, "GetManagedObjects");
}
/**
 * @brief Get ancestor objects from object mapper
 *
 * Queries for parent objects in the D-Bus object hierarchy.
 *
 * @tparam DictType Expected return type
 * @param bus D-Bus connection object
 * @param path D-Bus object path to find ancestors for
 * @param interfaces Optional filter for specific interfaces
 * @return AwaitableResult<DictType> Tuple of [error_code, ancestors_map]
 */
template <typename DictType>
inline AwaitableResult<DictType> getAncestors(
    sdbusplus::asio::connection& bus, std::string path,
    std::vector<std::string> interfaces = {})
{
    co_return co_await awaitable_dbus_method_call<DictType>(
        bus, objectMapperService, objectMapperPath, objectMapperInterface,
        "GetAncestors", path, interfaces);
}

/**
 * @brief Introspect a D-Bus object
 *
 * Retrieves the XML introspection data for a D-Bus object.
 *
 * @param bus D-Bus connection object
 * @param service D-Bus service name
 * @param path D-Bus object path to introspect
 * @return AwaitableResult<std::string> Tuple of [error_code,
 * xml_introspection_data]
 */
inline AwaitableResult<std::string> introspect(sdbusplus::asio::connection& bus,
                                               std::string service,
                                               sdbuscompat::object_path path)
{
    // NOLINTNEXTLINE(clang-analyzer-core.NullDereference)
    co_return co_await awaitable_dbus_method_call<std::string>(
        bus, service, path, dbusIntrospectableInterface, "Introspect");
}
/**
 * @brief Get default value for a type
 *
 * Returns a default-constructed value for the specified type.
 * Can be specialized for types requiring non-default initialization.
 *
 * @tparam T Type to get default value for
 * @return T Default value for the type
 */
template <typename T>
T getDefaultValue()
{
    return {};
}

/**
 * @brief Extract a typed property value from a PropertyMap
 *
 * Safely extracts and converts a property value from a PropertyMap with
 * type checking and error handling.
 *
 * @tparam T Expected type of the property
 * @param ec Error code (set if property not found or type mismatch)
 * @param propMap Property map to search in
 * @param argname Property name to extract
 * @return T Property value or default value if error
 *
 * @note Sets ec to not_found if property missing, invalid_argument if type
 * mismatch
 */
template <typename T>
T getPropertyFromMap(boost::system::error_code& ec, const PropertyMap& propMap,
                     std::string_view argname)
{
    if (ec)
    {
        LOG_ERROR("Already failed for previous properties in map retrieval");
        return getDefaultValue<T>();
    }
    auto iter = propMap.find(std::string(argname));
    if (iter == propMap.end())
    {
        LOG_ERROR("Failed to find property {}", argname);
        ec = boost::asio::error::not_found;
        return getDefaultValue<T>();
    }
    if (!std::holds_alternative<T>(iter->second))
    {
        LOG_ERROR("Type mismatch for property {}", argname);
        ec = boost::asio::error::invalid_argument;
        return getDefaultValue<T>();
    }
    return std::get<T>(iter->second);
}

/**
 * @brief Implementation helper for getPropertiesFromMap
 *
 * Sequentially extracts each property in order. Once an error is set,
 * all remaining properties are left as their default-constructed values.
 *
 * @tparam ArgTypes Types of properties to extract
 * @tparam Args Property name types
 * @tparam I Index sequence for parameter pack expansion
 */
template <typename... ArgTypes, typename... Args, std::size_t... I>
inline std::tuple<ArgTypes...> getPropertiesFromMapImpl(
    boost::system::error_code& ec, const PropertyMap& propMap,
    std::index_sequence<I...>, const Args&... args)
{
    // Make sure ArgTypes and Args have the same size
    static_assert(sizeof...(ArgTypes) == sizeof...(Args),
                  "Size mismatch between types and arguments");
    std::tuple<ArgTypes...> result{};
    // Fold over indices left-to-right; once ec is set the per-property
    // function returns the default value immediately (see getPropertyFromMap).
    // NOLINTBEGIN(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    ((std::get<I>(result) =
          getPropertyFromMap<std::tuple_element_t<I, std::tuple<ArgTypes...>>>(
              ec, propMap, std::get<I>(std::forward_as_tuple(args...)))),
     ...);
    // NOLINTEND(cppcoreguidelines-pro-bounds-array-to-pointer-decay)
    return result;
}

/**
 * @brief Extract multiple typed properties from a PropertyMap
 *
 * Convenience function to extract multiple properties at once with type safety.
 *
 * @tparam ArgTypes Types of properties to extract (in order)
 * @tparam Args Property name types
 * @param propMap Property map to search in
 * @param args Property names to extract (in order matching ArgTypes)
 * @return std::tuple<error_code, ArgTypes...> Error code and extracted values
 *
 * @note Stops at first error; subsequent values will be default-constructed
 *
 * Example:
 * @code
 * auto [ec, enabled, speed, name] = getPropertiesFromMap<bool, uint32_t,
 * std::string>( propMap, "NICEnabled", "Speed", "InterfaceName"); if (!ec) {
 *     // Use enabled, speed, name
 * }
 * @endcode
 */
template <typename... ArgTypes, typename... Args>
inline std::tuple<boost::system::error_code, ArgTypes...> getPropertiesFromMap(
    const PropertyMap& propMap, const Args&... args)
{
    boost::system::error_code ec{};
    auto t = getPropertiesFromMapImpl<ArgTypes...>(
        ec, propMap, std::index_sequence_for<ArgTypes...>{}, args...);
    return std::tuple_cat(std::make_tuple(ec), t);
}
// NOLINTEND(cppcoreguidelines-avoid-reference-coroutine-parameters)
} // namespace NSNAME
