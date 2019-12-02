httop
------------

## Requirements
- This tool depends on libcap which ships with osx.
- This tool uses go modules. Clone to a directory outside of your GOPATH.

## Usage
- Build or install with standard go build or go install commands (go build).
- This tool typically requires elevated permissions to capture packets. Most users can use sudo
- For help use `./httop -h`
- Example usage: `sudo ./httop -gui -debug`

## Known issues / future improvements
- Stats collection is very primitive. It uses a list of all events and
  trims/aggregates them when needed. This could be improved by using an in-
  memory bucketed timeseries database instead of storing raw events
- There's a tiny bit of lock contention between sending events to the stats and
  aggregating them for display. Definitely some room for improvement there as
  well.
- Active alerts are held in the state of the text display. Ideally there'd be a
  thing that a Display could subscribe to for updates on alert states rather
  than managing state in the view.
