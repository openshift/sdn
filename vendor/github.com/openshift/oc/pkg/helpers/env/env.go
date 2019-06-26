package env

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation"
)

var argumentEnvironment = regexp.MustCompile(`(?ms)^(.+)\=(.*)$`)

func IsEnvironmentArgument(s string) bool {
	return argumentEnvironment.MatchString(s)
}

func SplitEnvironmentFromResources(args []string) (resources, envArgs []string, ok bool) {
	first := true
	for _, s := range args {
		// this method also has to understand env removal syntax, i.e. KEY-
		isEnv := IsEnvironmentArgument(s) || strings.HasSuffix(s, "-")
		switch {
		case first && isEnv:
			first = false
			fallthrough
		case !first && isEnv:
			envArgs = append(envArgs, s)
		case first && !isEnv:
			resources = append(resources, s)
		case !first && !isEnv:
			return nil, nil, false
		}
	}
	return resources, envArgs, true
}

// parseIntoEnvVar parses the list of key-value pairs into kubernetes EnvVar.
// envVarType is for making errors more specific to user intentions.
func parseIntoEnvVar(spec []string, defaultReader io.Reader, envVarType string) ([]corev1.EnvVar, []string, error) {
	env := []corev1.EnvVar{}
	exists := sets.NewString()
	var remove []string
	for _, envSpec := range spec {
		switch {
		case envSpec == "-":
			if defaultReader == nil {
				return nil, nil, fmt.Errorf("when '-' is used, STDIN must be open")
			}
			fileEnv, err := readEnv(defaultReader, envVarType)
			if err != nil {
				return nil, nil, err
			}
			env = append(env, fileEnv...)
		case strings.Contains(envSpec, "="):
			parts := strings.SplitN(envSpec, "=", 2)
			n, v := parts[0], parts[1]
			if errs := validation.IsEnvVarName(n); len(errs) != 0 {
				return nil, nil, fmt.Errorf("%s %s is invalid, %s", envVarType, envSpec, strings.Join(errs, "; "))
			}
			exists.Insert(n)
			env = append(env, corev1.EnvVar{
				Name:  n,
				Value: v,
			})
		case strings.HasSuffix(envSpec, "-"):
			remove = append(remove, envSpec[:len(envSpec)-1])
		default:
			return nil, nil, fmt.Errorf("%ss must be of the form key=value, but is %q", envVarType, envSpec)
		}
	}
	for _, removeLabel := range remove {
		if _, found := exists[removeLabel]; found {
			return nil, nil, fmt.Errorf("can not both modify and remove the same %s in the same command", envVarType)
		}
	}
	return env, remove, nil
}

func ParseBuildArg(spec []string, defaultReader io.Reader) ([]corev1.EnvVar, error) {
	env, _, err := parseIntoEnvVar(spec, defaultReader, "build-arg")
	return env, err
}

func ParseEnv(spec []string, defaultReader io.Reader) ([]corev1.EnvVar, []string, error) {
	return parseIntoEnvVar(spec, defaultReader, "environment variable")
}

func ParseAnnotation(spec []string, defaultReader io.Reader) (map[string]string, []string, error) {
	vars, remove, err := parseIntoEnvVar(spec, defaultReader, "annotation")
	annotations := make(map[string]string)
	for _, v := range vars {
		annotations[v.Name] = v.Value
	}
	return annotations, remove, err
}

func readEnv(r io.Reader, envVarType string) ([]corev1.EnvVar, error) {
	env := []corev1.EnvVar{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		envSpec := scanner.Text()
		if pos := strings.Index(envSpec, "#"); pos != -1 {
			envSpec = envSpec[:pos]
		}
		if strings.Contains(envSpec, "=") {
			parts := strings.SplitN(envSpec, "=", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid %s: %v", envVarType, envSpec)
			}
			env = append(env, corev1.EnvVar{
				Name:  parts[0],
				Value: parts[1],
			})
		}
	}
	if err := scanner.Err(); err != nil && err != io.EOF {
		return nil, err
	}
	return env, nil
}
