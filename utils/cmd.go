package utils

import (
	"asterfusion/client/logger"
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Common commands
const rebootCMD string = "reboot"
const factoryCMD string = "config load_default_settings -m -y"
const default_work_space string = "/home/admin"
const clishScriptFile string = "/usr/local/bin/scripts/clish.sh"

func argFormat(arg []string) string {
	return fmt.Sprintf("\"%s\"", strings.Join(arg, "\", \""))
}

// RunCommand - Execute the command.
//
//	@param name - execute file
//	@param env - command.Env
//	@param arg - arg of execute file
//	@return exit - shell command line exit status code
//	@return ouput
//		    when exec cmd success, ouput is stdout
//		    when exec cmd failed, ouput is stderr
func RunCommand(name string, env []string, arg ...string) (exit uint8, output string) {
	if len(arg) == 0 {
		return 0, "The command to be executed is nil."
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	uuid := fmt.Sprintf("%v", time.Now().Unix())
	command := exec.Command(name, arg...)
	command.Dir = default_work_space
	command.Stdout = &stdout
	command.Stderr = &stderr
	command.Env = env
	// Remove cmd log print
	// logger.Info("[%s] Command [%q %q] execution started.", uuid, name, argFormat(arg))

	err := command.Run()
	if err != nil {
		logger.Error("[%s] Command [%q %q] failed with error: %q. Stderr: %q", uuid, name, argFormat(arg), err.Error(), stderr.String())
		codestr := strings.TrimPrefix(err.Error(), "exit status ")
		code, e := strconv.Atoi(codestr)
		if e != nil {
			code = 1
		}
		return uint8(code), stderr.String()
	}
	// Remove cmd log print
	// logger.Info("[%s] Command [%q %q]  executed successfully.", uuid, name, argFormat(arg))
	return 0, stdout.String()
}

// RunCommand - Execute the command with timeout.
//
//		@param ctx - context.WithTimeout()
//		@param name - execute file
//		@param env - command.Env
//		@param arg - arg of execute file
//		@return exit - shell command line exit status code
//	              - 255 timeout
//		@return ouput
//			    when exec cmd success, ouput is stdout
//			    when exec cmd failed, ouput is stderr
//			    when exec cmd canceled, ouput is "timeout"
func RunCommandWithTimeout(ctx context.Context, name string, env []string, arg ...string) (exit uint8, output string) {
	if len(arg) == 0 {
		return 0, "The command to be executed is nil."
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	uuid := fmt.Sprintf("%v", time.Now().Unix())
	command := exec.CommandContext(ctx, name, arg...)
	command.Dir = default_work_space
	command.Env = env
	command.Stdout = &stdout
	command.Stderr = &stderr

	logger.Info("[%s] Command [%q %q] execution started.", uuid, name, argFormat(arg))

	errChan := make(chan error)
	go func() {
		errChan <- command.Run()
	}()

	select {
	case <-ctx.Done():
		logger.Info("[%s] Command [%q %q] canceled.", uuid, name, argFormat(arg))
		if command.Process != nil {
			if err := command.Process.Kill(); err != nil {
				logger.Warn("Failed to kill process with error: %q", err.Error())
			}
		}
		return 255, "Timed out."
	case err := <-errChan:
		if err != nil {
			logger.Error("[%s] Command [%q %q] failed with error: %q. Stderr: %q", uuid, name, argFormat(arg), err.Error(), stderr.String())

			codestr := strings.TrimPrefix(err.Error(), "exit status ")
			code, e := strconv.Atoi(codestr)
			if e != nil {
				code = 1
			}
			return uint8(code), stderr.String()
		}

		logger.Info("[%s] Command [%q %q]  executed successfully.", uuid, name, argFormat(arg))
		return 0, stdout.String()
	}
}

// RunShellCommand - Execute the command on the sh.
//
//	@param cmd - same as RunCommand, but no No shell arguments required
//	@return exit - same as RunCommand
//	@return output - same as RunCommand
func RunShellCommand(cmd string) (exit uint8, ouput string) {
	env := []string{}
	return RunCommand("bash", env, "-c", cmd)
}

func RunShellCommandWithTimeout(cmd string, timeout uint) (exit uint8, ouput string) {
	if timeout <= 0 {
		return 1, "Timeout must be greater than 0"
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(timeout))
	defer cancel()

	env := []string{}
	return RunCommandWithTimeout(ctx, "bash", env, "-c", cmd)
}

// RunSonicCommand - Execute the command on the sh.
//
//	@param cmd - same as RunCommand, but no No shell arguments required
//	@return exit - same as RunCommand
//	@return output - same as RunCommand
func RunSonicCommand(cmd string) (exit uint8, ouput string) {
	env := []string{"CONFIG_VIEW=true"}
	return RunCommand("bash", env, "-c", cmd)
}

// RunRebootCommand - Execute the reboot command on the sh.
//
//	@return exit - same as RunCommand
//	@return output - same as RunCommand
func RunRebootCommand() (exit uint8, ouput string) {
	return RunShellCommand(rebootCMD)
}

// RebootWithLog
//
//	@param time - Task added in %t.
//	@param detail - Description.
func RebootWithLog(time time.Time, detail string) {
	logger.Info("Execute the reboot task.Task added in %s.%q", time.Format("2006-01-02 15:04:05"), detail)
	exit, msg := RunRebootCommand()
	if exit != 0 {
		logger.Error("Device reboot failed, exit code: %d, error: %q.", exit, msg)
	}
}

// RebootDelay
//
//	@param when - When to exec task.
//	@param detail - Description.
func RebootDelay(when uint, detail string) {
	now := time.Now()
	time.AfterFunc(time.Duration(when)*time.Second, func() { RebootWithLog(now, detail) })
}

// RunFactoryCommand
//
//	@return exit - same as RunCommand
//	@return output - same as RunCommand
func RunFactoryCommand() (exit uint8, ouput string) {
	exit, ouput = RunSonicCommand(factoryCMD)
	if exit > 0 {
		return
	}
	// remove /etc/ucentral/ucentral.active
	exit, ouput = RunShellCommand("rm /etc/ucentral/ucentral*")
	if exit > 0 {
		return
	}

	when := 15
	logger.Info("Execute the reboot task after %d seconds.", when)
	RebootDelay(uint(when), "Task added by factory command.")

	return
}

func RunShellScript(path string) (exit uint8, ouput string) {
	return RunShellCommand(path)
}

func RunShellScriptWithTimeout(path string, timeout uint) (exit uint8, ouput string) {
	if timeout <= 0 {
		return 1, "Timeout must be greater than 0"
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(timeout))
	defer cancel()

	env := []string{}
	return RunCommandWithTimeout(ctx, "bash", env, "-c", path)
}

func RunClishCommandWithTimeout(cmd string, timeout uint) (exit uint8, output string) {
	if timeout <= 0 {
		return 1, "Timeout must be greater than 0"
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*time.Duration(timeout))
	defer cancel()

	env := []string{}
	return RunCommandWithTimeout(ctx, clishScriptFile, env, "-w", "configure-view", "-c", cmd)
}
