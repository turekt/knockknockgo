# Firewall log monitoring

Since `tail` command is not implemented in Go as it is supported natively in Python via sh module, there was an additional need for implementing file monitoring in knockknockgo. There seems to be at least two Go libraries available for file monitoring that can be included in the project for easier `tail`-ing, but by following the [minimal dependency philosophy](LIBRARIES.md), own simple solution was the best approach forward.

Since knockknockgo is heavily targeted on Linux, we can incorporate inotify in order to add hooks on files that will hold firewall logs. The `LogWatcher` adds a watch for the following inotify events:
- `syscall.IN_DELETE_SELF | syscall.IN_MOVE_SELF | syscall.IN_MOVE | syscall.IN_DELETE`
  - used in case file is deleted or moved, this situation is handled by initiating a wait until another log file to show up
- `syscall.IN_CLOSE_WRITE | syscall.IN_MODIFY`
  - used when file content was changed, might mean that a fresh firewall log was inserted
  - when this event is received, log file is opened and read from where the goroutine left off
  - any new log line in the firewall log is sent to `LogHandler` for further processing
- `syscall.IN_IGNORED`
  - used to exit the goroutine cleanly, it is expected that the interrupt handler goroutine issues this event when OS interrupt is issued
  - subsequent exits will also issue a close on a channel that is being listened by `LogHandler` to propagate clean exit on all goroutines