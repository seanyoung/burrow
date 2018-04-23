package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"io/ioutil"

	"github.com/hyperledger/burrow/config"
	"github.com/hyperledger/burrow/config/source"
	"github.com/hyperledger/burrow/execution"
	"github.com/hyperledger/burrow/genesis"
	"github.com/hyperledger/burrow/genesis/spec"
	"github.com/hyperledger/burrow/keys"
	"github.com/hyperledger/burrow/logging"
	logging_config "github.com/hyperledger/burrow/logging/config"
	"github.com/hyperledger/burrow/logging/config/presets"
	"github.com/hyperledger/burrow/project"
	"github.com/jawher/mow.cli"
)

func main() {
	burrow := cli.App("burrow", "The EVM smart contract machine with Tendermint consensus")

	genesisOpt := burrow.StringOpt("g genesis", "",
		"Use the specified genesis JSON file rather than a key in the main config, use - to read from STDIN")

	configOpt := burrow.StringOpt("c config", "",
		"Use the a specified burrow config TOML file")

	versionOpt := burrow.BoolOpt("v version", false, "Print the Burrow version")

	burrow.Spec = "[--config=<config file>] [--genesis=<genesis json file>] [--version]"

	burrow.Action = func() {
		if *versionOpt {
			fmt.Println(project.FullVersion())
			os.Exit(0)
		}
		// We need to reflect on whether this obscures where values are coming from
		conf := config.DefaultBurrowConfig()
		// We treat logging a little differently in that if anything is set for logging we will not
		// set default outputs
		conf.Logging = nil
		err := source.EachOf(
			burrowConfigProvider(*configOpt),
			source.FirstOf(
				genesisDocProvider(*genesisOpt, false),
				// Try working directory
				genesisDocProvider(config.DefaultGenesisDocJSONFileName, true)),
		).Apply(conf)
		// If no logging config was provided use the default
		if conf.Logging == nil {
			conf.Logging = logging_config.DefaultNodeLoggingConfig()
		}
		if err != nil {
			fatalf("could not obtain config: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		kern, err := conf.Kernel(ctx)
		if err != nil {
			fatalf("could not create Burrow kernel: %v", err)
		}

		err = kern.Boot()
		if err != nil {
			fatalf("could not boot Burrow kernel: %v", err)
		}
		kern.WaitForShutdown()
	}

	burrow.Command("spec",
		"Build a GenesisSpec that acts as a template for a GenesisDoc and the configure command",
		func(cmd *cli.Cmd) {
			tomlOpt := cmd.BoolOpt("t toml", false, "Emit GenesisSpec as TOML rather than the "+
				"default JSON")

			fullOpt := cmd.IntOpt("f full-accounts", 1, "Number of preset Full type accounts")
			validatorOpt := cmd.IntOpt("v validator-accounts", 0, "Number of preset Validator type accounts")
			rootOpt := cmd.IntOpt("r root-accounts", 0, "Number of preset Root type accounts")
			developerOpt := cmd.IntOpt("d developer-accounts", 0, "Number of preset Developer type accounts")
			participantsOpt := cmd.IntOpt("p participant-accounts", 1, "Number of preset Participant type accounts")
			chainNameOpt := cmd.StringOpt("n chain-name", "", "Default chain name")

			cmd.Spec = "[--full-accounts] [--validator-accounts] [--root-accounts] [--developer-accounts] [--participant-accounts] [--chain-name] [--toml]"

			cmd.Action = func() {
				specs := make([]spec.GenesisSpec, 0, *participantsOpt+*fullOpt)
				for i := 0; i < *fullOpt; i++ {
					specs = append(specs, spec.FullAccount(i))
				}
				for i := 0; i < *validatorOpt; i++ {
					specs = append(specs, spec.ValidatorAccount(i))
				}
				for i := 0; i < *rootOpt; i++ {
					specs = append(specs, spec.RootAccount(i))
				}
				for i := 0; i < *developerOpt; i++ {
					specs = append(specs, spec.DeveloperAccount(i))
				}
				for i := 0; i < *participantsOpt; i++ {
					specs = append(specs, spec.ParticipantAccount(i))
				}
				genesisSpec := spec.MergeGenesisSpecs(specs...)
				genesisSpec.ChainName = *chainNameOpt
				if *tomlOpt {
					os.Stdout.WriteString(source.TOMLString(genesisSpec))
				} else {
					os.Stdout.WriteString(source.JSONString(genesisSpec))
				}
			}
		})

	burrow.Command("configure",
		"Create Burrow configuration by consuming a GenesisDoc or GenesisSpec, creating keys, and emitting the config",
		func(cmd *cli.Cmd) {
			genesisSpecOpt := cmd.StringOpt("s genesis-spec", "",
				"A GenesisSpec to use as a template for a GenesisDoc that will be created along with keys")

			tomlInOpt := cmd.BoolOpt("t toml-in", false, "Consume GenesisSpec/GenesisDoc as TOML "+
				"rather than the JSON default")

			keysUrlOpt := cmd.StringOpt("k keys-url", "", fmt.Sprintf("Provide keys URL, default: %s",
				keys.DefaultKeysConfig().URL))

			jsonOutOpt := cmd.BoolOpt("j json-out", false, "Emit config in JSON rather than TOML "+
				"suitable for further processing or forming a separate genesis.json GenesisDoc")

			genesisDocOpt := cmd.StringOpt("g genesis-doc", "", "GenesisDoc JSON to embed in config")

			separateGenesisDoc := cmd.StringOpt("s separate-genesis-doc", "", "Emit a separate genesis doc as JSON")

			validatorIndexOpt := cmd.IntOpt("v validator-index", -1,
				"Validator index (in validators list - GenesisSpec or GenesisDoc) from which to set ValidatorAddress")

			loggingOpt := cmd.StringOpt("l logging", "",
				"Comma separated list of logging instructions which form a 'program' which is a depth-first "+
					"pre-order of instructions that will build the root logging sink. See 'burrow help' for more information.")

			describeLoggingOpt := cmd.BoolOpt("describe-logging", false,
				"Print an exhaustive list of logging instructions available with the --logging option")

			debugOpt := cmd.BoolOpt("d debug", false, "Include maximal debug options in config "+
				"including logging opcodes and dumping EVM tokens to disk these can be later pruned from the "+
				"generated config.")

			chainNameOpt := cmd.StringOpt("n chain-name", "", "Default chain name")

			cmd.Spec = "[--keys-url=<keys URL>] [--genesis-spec=<GenesisSpec file> | --genesis-doc=<GenesisDoc file>] " +
				"[--separate-genesis-doc=<genesis JSON file>]" +
				"[--validator-index=<index>] [--chain-name] [--toml-in] [--json-out] " +
				"[--logging=<logging program>] [--describe-logging] [--debug]"

			cmd.Action = func() {
				conf := config.DefaultBurrowConfig()

				if *configOpt != "" {
					// If explicitly given a config file use it as a base:
					err := source.FromTOMLFile(*configOpt, conf)
					if err != nil {
						fatalf("could not read base config file (as TOML): %v", err)
					}
				}

				if *describeLoggingOpt {
					fmt.Printf("Usage:\n  burrow configure -l INSTRUCTION[,...]\n\nBuilds a logging " +
						"configuration by constructing a tree of logging sinks assembled from preset instructions " +
						"that generate the tree while traversing it.\n\nLogging Instructions:\n")
					for _, instruction := range presets.Instructons() {
						fmt.Printf("  %-15s\t%s\n", instruction.Name(), instruction.Description())
					}
					fmt.Printf("\nExample Usage:\n  burrow configure -l include-any,info,stderr\n")
					return
				}

				if *keysUrlOpt != "" {
					conf.Keys.URL = *keysUrlOpt
				}

				if *genesisSpecOpt != "" {
					genesisSpec := new(spec.GenesisSpec)
					err := fromFile(*genesisSpecOpt, *tomlInOpt, genesisSpec)
					if err != nil {
						fatalf("could not read GenesisSpec: %v", err)
					}
					keyClient := keys.NewKeyClient(conf.Keys.URL, logging.NewNoopLogger())
					conf.GenesisDoc, err = genesisSpec.GenesisDoc(keyClient)
					if err != nil {
						fatalf("could not realise GenesisSpec: %v", err)
					}
				} else if *genesisDocOpt != "" {
					genesisDoc := new(genesis.GenesisDoc)
					err := fromFile(*genesisSpecOpt, *tomlInOpt, genesisDoc)
					if err != nil {
						fatalf("could not read GenesisSpec: %v", err)
					}
					conf.GenesisDoc = genesisDoc
				}

				if *validatorIndexOpt > -1 {
					if conf.GenesisDoc == nil {
						fatalf("Unable to set ValidatorAddress from provided validator-index since no " +
							"GenesisDoc/GenesisSpec provided.")
					}
					if len(conf.GenesisDoc.Validators) < *validatorIndexOpt {
						fatalf("validator-index of %v given but only %v validators specified in GenesisDoc",
							*validatorIndexOpt, len(conf.GenesisDoc.Validators))
					}
					conf.ValidatorAddress = &conf.GenesisDoc.Validators[*validatorIndexOpt].Address
				} else if conf.GenesisDoc != nil && len(conf.GenesisDoc.Validators) > 0 {
					// Pick first validator otherwise - might want to change this when we support non-validating node
					conf.ValidatorAddress = &conf.GenesisDoc.Validators[0].Address
				}

				if *loggingOpt != "" {
					ops := strings.Split(*loggingOpt, ",")
					sinkConfig, err := presets.BuildSinkConfig(ops...)
					if err != nil {
						fatalf("could not build logging configuration: %v\n\nTo see possible logging "+
							"instructions run:\n  burrow configure --describe-logging", err)
					}
					conf.Logging = &logging_config.LoggingConfig{
						RootSink: sinkConfig,
					}
				}

				if *debugOpt {
					conf.Execution = &execution.ExecutionConfig{
						VMOptions: []execution.VMOption{execution.DumpTokens, execution.DebugOpcodes},
					}
				}

				if *chainNameOpt != "" {
					if conf.GenesisDoc == nil {
						fatalf("Unable to set ChainName since no GenesisDoc/GenesisSpec provided.")
					}
					conf.GenesisDoc.ChainName = *chainNameOpt
				}

				if *separateGenesisDoc != "" {
					if conf.GenesisDoc == nil {
						fatalf("Cannot write separate genesis doc since no GenesisDoc/GenesisSpec provided.")
					}
					genesisDocJSON, err := conf.GenesisDoc.JSONBytes()
					if err != nil {
						fatalf("Could not form GenesisDoc JSON: %v", err)
					}
					err = ioutil.WriteFile(*separateGenesisDoc, genesisDocJSON, 0700)
					if err != nil {
						fatalf("Could not write GenesisDoc JSON: %v", err)
					}
					conf.GenesisDoc = nil
				}
				if *jsonOutOpt {
					os.Stdout.WriteString(conf.JSONString())
				} else {
					os.Stdout.WriteString(conf.TOMLString())
				}
			}
		})

	burrow.Command("keys",
		"A tool for doing a bunch of cool stuff with keys",
		func(cmd *cli.Cmd) {
			if keysHost := os.Getenv("MONAX_KEYS_HOST"); keysHost != "" {
				keys.DefaultHost = keysHost
			}
			if keysPort := os.Getenv("MONAX_KEYS_PORT"); keysPort != "" {
				keys.DefaultPort = keysPort
			}

			keys.KeyHost = *cmd.StringOpt("host", keys.DefaultHost, "set the host for talking to the key daemon")

			keys.KeyPort = *cmd.StringOpt("port", keys.DefaultPort, "set the port for key daemon")

			cmd.Command("server", "run keys server", func(cmd *cli.Cmd) {
				keys.KeysDir = *cmd.StringOpt("dir", keys.DefaultDir, "specify the location of the directory containing key files")

				cmd.Action = func() {
					keys.StartServer(keys.KeyHost, keys.KeyPort)
				}
			})

			cmd.Command("gen", "Generates a key using (insert crypto pkgs used)", func(cmd *cli.Cmd) {
				keys.NoPassword = *cmd.BoolOpt("no-pass", false, "don'stringt use a password for this key")

				keyType := cmd.StringOpt("t type", "ed25519,ripemd160", "specify the type of key to create. Supports 'secp256k1,sha3' (ethereum),  'secp256k1,ripemd160sha2' (bitcoin), 'ed25519,ripemd160' (tendermint)")

				keyName := cmd.StringOpt("name", "", "name of key to use")

				cmd.Action = func() {
					keys.CliKeygen(*keyType, *keyName)
				}
			})

			cmd.Command("hash", "hash <some data>", func(cmd *cli.Cmd) {
				keys.HashType = *cmd.StringOpt("t type", keys.DefaultHashType, "specify the hash function to use")

				keys.HexByte = *cmd.BoolOpt("hex", false, "the input should be hex decoded to bytes first")

				msg := cmd.StringArg("MSG", "", "message to hash")

				cmd.Action = func() {
					keys.CliHash(*msg)
				}
			})

			cmd.Command("import", "import <priv key> | /path/to/keyfile | <key json>", func(cmd *cli.Cmd) {
				keys.NoPassword = *cmd.BoolOpt("no-pass", false, "don't use a password for this key")

				keyType := cmd.StringOpt("t type", "ed25519,ripemd160", "specify the type of key to create. Supports 'secp256k1,sha3' (ethereum),  'secp256k1,ripemd160sha2' (bitcoin), 'ed25519,ripemd160' (tendermint)")
				privKey := cmd.StringArg("KEY", "", "private key, filename, or raw json")

				cmd.Action = func() {
					keys.CliImport(*privKey, *keyType)
				}
			})

			cmd.Command("lock", "lock a key", func(cmd *cli.Cmd) {
				keys.KeyName = *cmd.StringOpt("name", "", "name of key to use")
				keys.KeyAddr = *cmd.StringOpt("addr", "", "address of key to use")

				cmd.Action = func() {
					keys.CliLock()
				}
			})

			cmd.Command("unlock", "unlock an unlocked key by supplying the password", func(cmd *cli.Cmd) {
				keys.KeyName = *cmd.StringOpt("name", "", "name of key to use")
				keys.KeyAddr = *cmd.StringOpt("addr", "", "address of key to use")

				cmd.Action = func() {
					keys.CliUnlock()
				}
			})

			cmd.Command("pub", "public key", func(cmd *cli.Cmd) {
				keys.KeyName = *cmd.StringOpt("name", "", "name of key to use")
				keys.KeyAddr = *cmd.StringOpt("addr", "", "address of key to use")

				cmd.Action = func() {
					keys.CliPub()
				}
			})

			cmd.Command("sign", "sign <some data>", func(cmd *cli.Cmd) {
				keys.KeyName = *cmd.StringOpt("name", "", "name of key to use")
				keys.KeyAddr = *cmd.StringOpt("addr", "", "address of key to use")

				msg := cmd.StringArg("MSG", "", "message to hash")

				cmd.Action = func() {
					keys.CliSign(*msg)
				}
			})

			cmd.Command("verify", "verify <some data> <sig>", func(cmd *cli.Cmd) {
				keys.KeyName = *cmd.StringOpt("name", "", "name of key to use")
				keys.KeyAddr = *cmd.StringOpt("addr", "", "address of key to use")

				msg := cmd.StringArg("MSG", "", "message to check")
				sig := cmd.StringArg("SIG", "", "signature")
				pub := cmd.StringArg("PUBLIC", "", "public key")

				cmd.Action = func() {
					keys.CliVerify(*msg, *sig, *pub)
				}
			})

			cmd.Command("name", "Manage keys name", func(cmd *cli.Cmd) {
				cmd.Command("add", "add key by name or addr", func(cmd *cli.Cmd) {
					name := *cmd.StringOpt("name", "", "name of key to use")
					addr := *cmd.StringOpt("addr", "", "address of key to use")

					cmd.Action = func() {
						keys.CliNameAdd(name, addr)
					}
				})

				cmd.Command("ls", "list key names", func(cmd *cli.Cmd) {
					cmd.Action = func() {
						keys.CliNameLs()
					}
				})

				cmd.Command("rm", "rm key by name", func(cmd *cli.Cmd) {
					name := cmd.StringArg("NAME", "", "key to remove")

					cmd.Action = func() {
						keys.CliNameRm(*name)
					}
				})
			})
		})

	burrow.Run(os.Args)
}

// Print informational output to Stderr
func printf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func fatalf(format string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func burrowConfigProvider(configFile string) source.ConfigProvider {
	return source.FirstOf(
		// Will fail if file doesn't exist, but still skipped it configFile == ""
		source.TOMLFile(configFile, false),
		source.Environment(config.DefaultBurrowConfigJSONEnvironmentVariable),
		// Try working directory
		source.TOMLFile(config.DefaultBurrowConfigTOMLFileName, true),
		source.Default(config.DefaultBurrowConfig()))
}

func genesisDocProvider(genesisFile string, skipNonExistent bool) source.ConfigProvider {
	return source.NewConfigProvider(fmt.Sprintf("genesis file at %s", genesisFile),
		source.ShouldSkipFile(genesisFile, skipNonExistent),
		func(baseConfig interface{}) error {
			conf, ok := baseConfig.(*config.BurrowConfig)
			if !ok {
				return fmt.Errorf("config passed was not BurrowConfig")
			}
			if conf.GenesisDoc != nil {
				return fmt.Errorf("sourcing GenesisDoc from file, but GenesisDoc was defined earlier " +
					"in config cascade, only specify GenesisDoc in one place")
			}
			genesisDoc := new(genesis.GenesisDoc)
			err := source.FromJSONFile(genesisFile, genesisDoc)
			if err != nil {
				return err
			}
			conf.GenesisDoc = genesisDoc
			return nil
		})
}

func fromFile(file string, toml bool, conf interface{}) (err error) {
	if toml {
		err = source.FromTOMLFile(file, conf)
		if err != nil {
			fatalf("could not read GenesisSpec: %v", err)
		}
	} else {
		err = source.FromJSONFile(file, conf)
		if err != nil {
			fatalf("could not read GenesisSpec: %v", err)
		}
	}
	return
}
