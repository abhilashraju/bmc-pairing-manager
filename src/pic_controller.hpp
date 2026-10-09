#pragma once

#include "beastdefs.hpp"
#include "i2c_client.hpp"
#include "logger.hpp"

#include <nlohmann/json.hpp>

#include <concepts>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>

/**
 * @brief PIC Pairing State values
 *
 * Represents the pairing state values returned by the PIC device over I2C.
 * This enum is trivially copyable and can be used with readTyped/writeTyped.
 */
enum class PairingState : uint8_t
{
    UNPAIRED = 0x00, ///< Device is not paired
    PAIRED = 0x55    ///< Device is paired
};

/**
 * @brief Convert PairingState to boolean
 */
constexpr bool toBool(PairingState state)
{
    return state == PairingState::PAIRED;
}

/**
 * @brief Convert boolean to PairingState
 */
constexpr PairingState fromBool(bool paired)
{
    return paired ? PairingState::PAIRED : PairingState::UNPAIRED;
}

/**
 * @brief Convert PairingState to string
 */
constexpr const char* toString(PairingState state)
{
    return state == PairingState::PAIRED ? "PAIRED" : "UNPAIRED";
}

/**
 * @brief PIC I2C Command structure
 *
 * Represents a 3-byte I2C command with header, command byte, and checksum.
 * Trivially copyable for use with writeTyped.
 */
struct PicCommand
{
    uint8_t header;   ///< Command header (always 0xFF)
    uint8_t command;  ///< Command byte
    uint8_t checksum; ///< Checksum byte

    /**
     * @brief Create a PIC command with automatic checksum calculation
     *
     * Checksum is the bitwise NOT of the command byte:
     *   checksum = ~cmd
     */
    static constexpr PicCommand create(uint8_t cmd)
    {
        return PicCommand{0xFF, cmd, static_cast<uint8_t>(~cmd)};
    }

    /**
     * @brief Command codes
     */
    static constexpr uint8_t CMD_READ_PAIRING_STATE = 0x81;
    static constexpr uint8_t CMD_BMC_PAIRED = 0x50;
};

/**
 * @brief Concept defining the PersistenceStrategy interface
 *
 * A PersistenceStrategy must provide methods to initialize, load, save,
 * and retrieve the pairing state.
 */
template <typename T>
concept PersistenceStrategy =
    requires(T strategy, PairingState state) {
        /**
         * @brief Initialize the persistence strategy
         * @return awaitable<bool> true if initialization succeeded
         */
        {
            strategy.initialize()
        } -> std::same_as<reactor::net::awaitable<bool>>;

        /**
         * @brief Load the current state
         * @return awaitable<void> completes when state is loaded
         */
        { strategy.loadState() } -> std::same_as<reactor::net::awaitable<void>>;

        /**
         * @brief Save the given state
         * @param state The state to save
         * @return awaitable<bool> true if save succeeded
         */
        {
            strategy.saveState(state)
        } -> std::same_as<reactor::net::awaitable<bool>>;

        /**
         * @brief Get the current state
         * @return bool The current state
         */
        { strategy.getState() } -> std::same_as<bool>;
    };

/**
 * @brief FileSystem-based persistence strategy
 *
 * Stores PIC state in a JSON file on the filesystem.
 * Uses synchronous file I/O operations.
 */
class FileSystemStrategy
{
  public:
    /**
     * @brief Construct a FileSystemStrategy
     * @param filePath Path to the JSON file (default:
     * /etc/bmc-pairing-manager/picctrl.json)
     */
    explicit FileSystemStrategy(
        std::string filePath = "/etc/bmc-pairing-manager/picctrl.json") :
        jsonFilePath(std::move(filePath))
    {
        loadStateFromJson();
    }

    /**
     * @brief Initialize the filesystem strategy
     * @return awaitable<bool> always returns true
     */
    static reactor::net::awaitable<bool> initialize()
    {
        co_return true;
    }

    /**
     * @brief Load state from JSON file
     * @return awaitable<void> completes when state is loaded
     */
    reactor::net::awaitable<void> loadState()
    {
        loadStateFromJson();
        co_return;
    }

    /**
     * @brief Save state to JSON file
     * @param newState The state to save
     * @return awaitable<bool> true if save succeeded
     */
    reactor::net::awaitable<bool> saveState(PairingState newState)
    {
        state = toBool(newState);
        co_return saveStateToJson();
    }

    /**
     * @brief Get the current state
     * @return bool The current state
     */
    bool getState() const
    {
        return state;
    }

  private:
    std::string jsonFilePath;
    bool state{false};

    /**
     * @brief Load state from JSON file
     */
    void loadStateFromJson()
    {
        try
        {
            if (std::filesystem::exists(jsonFilePath))
            {
                std::ifstream file(jsonFilePath);
                if (file.is_open())
                {
                    nlohmann::json j;
                    file >> j;
                    if (j.contains("state") && j["state"].is_boolean())
                    {
                        state = j["state"].get<bool>();
                        LOG_DEBUG("Loaded state from JSON: {}", state);
                    }
                }
            }
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to load state from JSON: {}", e.what());
            state = false;
        }
    }

    /**
     * @brief Save current state to JSON file
     * @return true if save was successful, false otherwise
     */
    bool saveStateToJson()
    {
        try
        {
            // Ensure directory exists
            std::filesystem::path filePath(jsonFilePath);
            std::filesystem::path dirPath = filePath.parent_path();

            if (!std::filesystem::exists(dirPath))
            {
                std::filesystem::create_directories(dirPath);
            }

            // Write JSON file
            nlohmann::json j;
            j["state"] = state;

            std::ofstream file(jsonFilePath);
            if (file.is_open())
            {
                file << j.dump(4); // Pretty print with 4 space indent
                file.close();
                LOG_DEBUG("Saved state to JSON: {}", state);
                return true;
            }
            return false;
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("Failed to save state to JSON: {}", e.what());
            return false;
        }
    }
};

/**
 * @brief I2C-based persistence strategy
 *
 * Stores PIC state via I2C communication with the PIC device.
 * The I2C slave device handles persistence internally.
 */
class I2CStrategy
{
  public:
    /**
     * @brief Construct an I2CStrategy
     * @param i2cBus I2C bus number (default: 3)
     * @param i2cAddress I2C slave address (default: 0x5a)
     */
    explicit I2CStrategy(int i2cBus = 3, uint16_t i2cAddress = 0x5a) :
        i2cBus(i2cBus), i2cAddress(i2cAddress),
        i2cDevicePath("/dev/i2c-" + std::to_string(i2cBus))
    {}

    /**
     * @brief Initialize I2C connection
     * @return awaitable<bool> true if initialization succeeded
     */
    reactor::net::awaitable<bool> initialize()
    {
        // Get executor from coroutine context
        // NOLINTNEXTLINE(clang-analyzer-core.CallAndMessage)
        auto executor = co_await reactor::net::this_coro::executor;

        // Create I2C client with the executor
        i2cClient.emplace(executor, i2cDevicePath, i2cAddress);

        auto openResult = co_await i2cClient->open();
        if (openResult != reactor::I2CError::Success)
        {
            LOG_ERROR("Failed to open I2C device: {}",
                      reactor::to_string(openResult));
            co_return false;
        }

        // Load state from I2C
        co_await loadState();
        co_return true;
    }

    /**
     * @brief Load state from I2C device
     * @return awaitable<void> completes when state is loaded
     */
    reactor::net::awaitable<void> loadState()
    {
        if (!i2cClient)
        {
            LOG_ERROR("I2C client not initialized");
            co_return;
        }

        // Write READ_PAIRING_STATE command using typed write
        PicCommand cmd = PicCommand::create(PicCommand::CMD_READ_PAIRING_STATE);
        auto writeResult = co_await i2cClient->writeTyped(cmd);
        if (!writeResult)
        {
            LOG_ERROR("Failed to write READ_PAIRING_STATE command: {}",
                      reactor::to_string(writeResult.error()));
            co_return;
        }

        // Read 1 byte response using typed read
        auto readResult = co_await i2cClient->readTyped<PairingState>();
        if (!readResult)
        {
            LOG_ERROR("Failed to read pairing state: {}",
                      reactor::to_string(readResult.error()));
            co_return;
        }

        // Parse state: 0x00 = UNPAIRED, 0x55 = PAIRED
        PairingState pairingState = *readResult;
        state = toBool(pairingState);

        LOG_INFO("Read pairing state from I2C: {} (0x{:02X})",
                 toString(pairingState), static_cast<uint8_t>(pairingState));
    }

    /**
     * @brief Save state via I2C
     * @param newState The state to save
     * @return awaitable<bool> true if save succeeded
     */
    reactor::net::awaitable<bool> saveState(PairingState newState)
    {
        if (!i2cClient)
        {
            LOG_ERROR("I2C client not initialized");
            co_return false;
        }

        if (newState == PairingState::UNPAIRED)
        {
            LOG_WARNING("Setting UNPAIRED state is not supported via I2C");
            state = false;
            co_return false;
        }

        // Set PAIRED state using typed command
        PicCommand cmd = PicCommand::create(PicCommand::CMD_BMC_PAIRED);
        auto writeResult = co_await i2cClient->writeTyped(cmd);
        if (!writeResult)
        {
            LOG_ERROR("Failed to set PAIRED state via I2C: {}",
                      reactor::to_string(writeResult.error()));
            co_return false;
        }

        LOG_INFO("Successfully set BMC to {} state via I2C",
                 toString(newState));
        state = toBool(newState);
        co_return true;
    }

    /**
     * @brief Get the current state
     * @return bool The current state
     */
    bool getState() const
    {
        return state;
    }

  private:
    int i2cBus;
    uint16_t i2cAddress;
    std::string i2cDevicePath;
    std::optional<reactor::I2CClient> i2cClient;
    bool state{false};
};
/**
 * @brief Compile-time strategy selection
 *
 * Define USE_FILESYSTEM_STRATEGY to use FileSystemStrategy,
 * otherwise I2CStrategy is used by default.
 */
#ifdef USE_FILESYSTEM_STRATEGY
using DefaultPersistenceStrategy = FileSystemStrategy;
#else
using DefaultPersistenceStrategy = I2CStrategy;
#endif

/**
 * @brief PicControllerImpl - Template implementation of PicController
 *
 * This class provides state management for PIC (Provisioning Interface
 * Controller) using a compile-time selected persistence strategy.
 *
 * @tparam Strategy The persistence strategy type (must satisfy
 * PersistenceStrategy concept)
 */
template <PersistenceStrategy Strategy>
class PicControllerImpl
{
  public:
    /**
     * @brief Construct a PicControllerImpl with FileSystem strategy
     * @param filePath Path to the JSON file (optional)
     */
    explicit PicControllerImpl(
        std::string filePath = "/etc/bmc-pairing-manager/picctrl.json")
        requires std::same_as<Strategy, FileSystemStrategy>
        : strategy(std::move(filePath))
    {}

    /**
     * @brief Construct a PicControllerImpl with I2C strategy parameters
     * @param i2cBus I2C bus number (default: 3)
     * @param i2cAddress I2C slave address (default: 0x5a)
     */
    explicit PicControllerImpl(int i2cBus = 3, uint16_t i2cAddress = 0x5a)
        requires std::same_as<Strategy, I2CStrategy>
        : strategy(i2cBus, i2cAddress)
    {}

    /**
     * @brief Construct a PicControllerImpl with custom strategy
     * @param strategy The persistence strategy instance
     */
    explicit PicControllerImpl(Strategy s) : strategy(std::move(s)) {}

    /**
     * @brief Initialize the persistence strategy
     * @return awaitable<bool> true if initialization succeeded
     */
    reactor::net::awaitable<bool> initialize()
    {
        co_return co_await strategy.initialize();
    }

    /**
     * @brief Set the PIC state
     * @param newState The new pairing state
     * @return awaitable<bool> true if state was successfully set
     */
    reactor::net::awaitable<bool> setState(PairingState newState)
    {
        co_return co_await strategy.saveState(newState);
    }

    /**
     * @brief Set the PIC state (bool overload for backward compatibility)
     * @param value The new state value (true = PAIRED, false = UNPAIRED)
     * @return awaitable<bool> true if state was successfully set
     */
    reactor::net::awaitable<bool> setState(bool value)
    {
        co_return co_await setState(fromBool(value));
    }

    /**
     * @brief Get the current PIC state
     * @return bool The current state
     */
    bool getState() const
    {
        return strategy.getState();
    }

    /**
     * @brief Load state from the persistence strategy
     * @return awaitable<void> completes when state is loaded
     */
    reactor::net::awaitable<void> loadState()
    {
        co_return co_await strategy.loadState();
    }

  private:
    Strategy strategy;
};

/**
 * @brief PicController - Non-template wrapper using default strategy
 *
 * This class provides backward compatibility by using the compile-time
 * selected default strategy (FileSystemStrategy or I2CStrategy).
 *
 * Strategy Selection:
 * - Define USE_FILESYSTEM_STRATEGY to use FileSystemStrategy
 * - Otherwise, I2CStrategy is used (default)
 */
class PicController : public PicControllerImpl<DefaultPersistenceStrategy>
{
  public:
    using PicControllerImpl<DefaultPersistenceStrategy>::PicControllerImpl;
};
