package task

type Task struct {
	ProcEnc     bool
	InputFile   string
	OutputFile  string
	ToStdout    bool
	RemoveInput bool
}
