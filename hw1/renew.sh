#!/bin/sh
rm pipes/*.pipe
mkfifo pipes/netforward_data.pipe pipes/netbackward_data.pipe
