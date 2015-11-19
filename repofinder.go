package main
import (
	"github.com/alexflint/go-arg"
	"fmt"
	"path/filepath"
	"os"
	"strings"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"io"
	"encoding/json"
	"net/http"
	"github.com/gorilla/mux"
	"strconv"
	"bytes"
)



type SSHClient struct {
	Config *ssh.ClientConfig
	Host   string
	Port   int
}

type SSHCommand struct {
	Path   string
	Env    []string
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
}
var args struct {
	Env       string    `arg:"-e,help:choose an environment to scan,required"`
	Locations []string `arg:"-l,help:search location origin"`
	Repo      string    `arg:"-r,help:pick a single repo to check"`
	Debug     bool    `arg:"-d,help:turn on debug mode"`
	Host      string    `args:"-H,help:URI of host to interogate,required"`
	Port      int    `args:"-P,help:SSH port of host,required"`
	File      string    `args:"-f,help:file containing commands to execute,required"`
}

type Context struct {
	Env    string `json:"env"`
	System []struct {
		Commands []string `json:"commands"`
		DNS      string   `json:"dns"`
		Port     string   `json:"port"`
		Channel  string   `json:"channel"`
		Name     string   `json:"name"`
	} `json:"system"`
}

type BuildInfo struct {
	Build_date         string `json:"build.date"`
	Build_version_full string `json:"build.version.full"`
}

type Versions struct {
	Env string `json:"env"`
	Vrs []Version `json:"versions"`
}

type Version struct {
	System    string `json:"system"`
	Channel   string `json:"channel"`
	Version   []string  `json:"version"`
	BuildInfo BuildInfo `json:"buildInfo"`
}


func (vers *Versions) AddVersion(version Version) []Version {
	vers.Vrs = append(vers.Vrs, version)
	return vers.Vrs
}

func (vers *Versions) AddEnv(env string) string {
	vers.Env = env
	return vers.Env
}
func (ver *Version) AddVer(vers []string) []string {
	ver.Version = vers
	return ver.Version
}
func (vers *Version) AddBuildInfo(buildInfo BuildInfo) BuildInfo {
	vers.BuildInfo = buildInfo
	return vers.BuildInfo
}

func init() {
	arg.MustParse(&args)

}

type prov struct {
	prov string
}

func main() {

	r := mux.NewRouter()
	r.HandleFunc("/getAgg", AggVersions)
	http.Handle("/", r)

	// Create client config

	fmt.Println("Listening...")
	http.ListenAndServe(":3000", nil)

	fmt.Printf("The environment you picked was --> %s\n ", args.Env)

	for _, loc := range args.Locations {

		if err := filepath.Walk(loc, func(path string, fileInfo os.FileInfo, _ error) error {
			if !(strings.Contains(path, ".git")) {
				if fileInfo.Mode().IsRegular() {
					fmt.Printf("The file %s is a file %t \n", path, fileInfo.Mode().IsRegular())
				}
			}
			return nil
		}); err != nil {
			fmt.Printf("The path to enlightenment was fraught  .........%s ,\n", err)
			os.Exit(1)
		}

	}

}

func AggVersions(w http.ResponseWriter, r *http.Request) {


	b, err := json.Marshal(ComposeJSON())
	if err != nil {
		fmt.Println("Error Marshalling struct j:", err)
		return
	}
	w.Write([]byte(b))

}

func ComposeJSON() *Versions {

	sshCnf := getSshConfig()

	versArry := make([]Version, 2)

	v := new(Versions)

	file, err1 := os.Open("commands.json")
	if err1 != nil {
		fmt.Println("Error:", err1)
	} //#2
	defer file.Close()
	fmt.Println("Hello json")

	decoder := json.NewDecoder(file)
	context := Context{}
	err := decoder.Decode(&context)
	if err != nil {
		fmt.Println("Error:", err)
	}
	v.AddEnv(context.Env)

	for i, system := range context.System {

		fmt.Printf("For %d get system --> %s at %s", i, system.Name, system.DNS)

		for i, cmd := range system.Commands {

			client := getSshClient(sshCnf, system.DNS, system.Port)

			commd := getSshCommand(cmd)

			fmt.Printf("Running command: %s\n", commd.Path)

			if (strings.Contains(system.Name, "agg-private")) {


			}

			if err, prov := client.RunCommand(commd); err != nil {
				fmt.Fprintf(os.Stderr, "command run error: %s\n", err)
				os.Exit(1)
			} else {

				if (strings.Contains(system.Name, "agg-private")) {
					decode := json.NewDecoder(bytes.NewReader([]uint8(prov.(string))))
					bi := BuildInfo{}
					err1 := decode.Decode(&bi)

					if err1 != nil {
						fmt.Println("Error: decoding build info", err1)
					} else {
						versArry[i] = Version{system.Name, "",nil, bi}
						v.AddVersion(versArry[i])
					}


				} else {

					str1 := strings.Split(prov.(string), ".jar")
					for n, x := range str1 {
						str1[n] = strings.TrimSpace(x)
					}

					for i, y := range str1 {
						fmt.Printf("No %d --yy--> %s\n", i, y)
					}


					versArry[i] = Version{system.Name, system.Channel,str1, BuildInfo{}}
					v.AddVersion(versArry[i])
				}
			}
		}
	}

	for _, vrs := range v.Vrs {


		fmt.Printf("Ranger\t\t\t-->%s<-- \n\t\t-->%s<-- \n", vrs.System, vrs.Version)
	}
	return v
}

func getSshClient(sshCnf *ssh.ClientConfig, host string, port string) *SSHClient {
	nPort, err := strconv.Atoi(port)
	if err != nil {
		fmt.Printf("Error: port number is invalid %s , %s", port, err)
	}
	client := &SSHClient{
		Config: sshCnf,
		Host:   host,
		Port:   nPort,
	}
	return client
}

func getSshCommand(commd string) *SSHCommand {

	cmd := &SSHCommand{
		Path:   commd,
		Env:    []string{""},
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}

	return cmd

}

func getSshConfig() *ssh.ClientConfig {

	sshConfig := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			PublicKeyFile("/Users/adrianjackson/.ssh/tsmkey05.pem"),
		},
	}
	return sshConfig

}
func PublicKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil
	}
	return ssh.PublicKeys(key)
}

func (client *SSHClient) RunCommand(cmd *SSHCommand) (error, interface{}) {
	rescueStdout := os.Stdout
	r, w, _ := os.Pipe()
	cmd.Stdout = w

	var (
		session *ssh.Session
		err error
	)

	if session, err = client.newSession(); err != nil {
		return err, nil
	}
	defer session.Close()

	if err = client.prepareCommand(session, cmd); err != nil {
		return err, nil
	}


	if err = session.Run(cmd.Path); err != nil {
		return err, nil
	}
	//err = session.Run(cmd.Path)
	//fmt.Printf("Err -> %s\n", err.Error())


	w.Close()

	out, _ := ioutil.ReadAll(r)
	os.Stdout = rescueStdout


	if (strings.Contains(cmd.Path, "providerLib")) {

		fmt.Printf("Jars ->%s<--\n\n", string([]byte(out)))

		fmt.Printf("\n\nRedone jars -->%s<--", strings.Replace(string([]byte(out)), "\n", "", 9999))


		//		s1 := string([]byte(out))[(strings.Index(string([]byte(out)), ".jar") - 7):(strings.Index(string([]byte(out)), ".jar"))]

		s1 := string([]byte(out))

		return err, s1
	} else if (strings.Contains(cmd.Path, "build")) {


		s1 := string([]byte(out))
		fmt.Printf("build-->%s<--", string(s1))

		return err, s1
	}


	return err, nil
}

// two byte-oriented functions identical except for operator comparing c to 127.
func stripCtlFromBytes(str string) string {
	b := make([]byte, len(str))
	var bl int
	for i := 0; i < len(str); i++ {
		c := str[i]
		if c >= 32 && c != 127 {
			b[bl] = c
			bl++
		}
	}
	return string(b[:bl])
}

func (client *SSHClient) newSession() (*ssh.Session, error) {
	connection, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", client.Host, client.Port), client.Config)
	if err != nil {
		return nil, fmt.Errorf("Failed to dial: %s", err)
	}

	session, err := connection.NewSession()
	if err != nil {
		return nil, fmt.Errorf("Failed to create session: %s", err)
	}

	modes := ssh.TerminalModes{
		// ssh.ECHO:          0,     // disable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}

	if err := session.RequestPty("xterm", 80, 80, modes); err != nil {
		session.Close()
		return nil, fmt.Errorf("request for pseudo terminal failed: %s", err)
	}

	return session, nil
}
func (client *SSHClient) prepareCommand(session *ssh.Session, cmd *SSHCommand) error {
	for _, env := range cmd.Env {
		variable := strings.Split(env, "=")
		if len(variable) != 2 {
			continue
		}

		if err := session.Setenv(variable[0], variable[1]); err != nil {
			return err
		}
	}

	if cmd.Stdin != nil {
		stdin, err := session.StdinPipe()
		if err != nil {
			return fmt.Errorf("Unable to setup stdin for session: %v", err)
		}
		go io.Copy(stdin, cmd.Stdin)
	}

	if cmd.Stdout != nil {
		stdout, err := session.StdoutPipe()
		if err != nil {
			return fmt.Errorf("Unable to setup stdout for session: %v", err)
		}

		go io.Copy(cmd.Stdout, stdout)
	}

	if cmd.Stderr != nil {
		stderr, err := session.StderrPipe()
		if err != nil {
			return fmt.Errorf("Unable to setup stderr for session: %v", err)
		}
		go io.Copy(cmd.Stderr, stderr)
	}

	return nil
}
