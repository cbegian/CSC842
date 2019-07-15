#!/usr/bin/env python3
#
# User Equipment (UE) Locator for Cycle 9
# Reads the location of three cell towers, and RSS or signal travel time
# values from a file, and triangulates the approximate location of the
# mobile device (also known as the "user equipmet" or "UE").
#
# The triangulated location is output at a KML file which can be graphically
# displayed by opening it in Google Earth Pro.

# This file has been formatted with "black" from https://github.com/python/black
import argparse
import simplekml
import math
from polycircles import polycircles


class Tower:
    # Creates a Tower object, setting the gelocation and signal strength.
    # Note that the signal strength is used later for RSS geolocation, but
    # not for geolocation based on signal travel time.
    def __init__(self, args):
        # Initalize id, tower location and signal strength.
        self.id = args[0]
        self.latitude = float(args[1])
        self.longitude = float(args[2])
        self.txFreqInHertz = float(args[3])
        self.txPowerInWatts = float(args[4])
        self.txAntennaGain = float(args[5])

    # Add location of this tower to the KML object.
    def plot(self, kml):
        # Note that the order of the lat and lon coordinates must be
        # reversed in the newpoint() call.
        point = kml.newpoint(name=self.id, coords=[(self.longitude, self.latitude)])
        point.style.iconstyle.icon.href = (
            "http://maps.google.com/mapfiles/kml/pal4/icon52.png"
        )
        return kml


class UEreading:
    # Creates a UEreading object, setting the tower, and RSS or signal travel
    # time values from that tower to the UE.
    def __init__(self, twr, args):
        self.tower = twr
        self.readingType = args[0]
        self.reading = float(args[1])

    # Computes the distance from the associated Tower object to the UE,
    # based on the type of reading (RSS or signal travel time).
    def distance(self):
        # Speed of light in meters per second
        SPEED_OF_LIGHT = 300000000
        FOUR_PI = 4.0 * math.pi

        # Receiver antenna gain is (for now) set at 1
        RX_GAIN = 1

        distanceToUE = 0.0

        # If this is a signal strength (RSS) reading...
        if self.readingType == "RSS":
            # First, compute wavelength of the signal
            wavelength = float(SPEED_OF_LIGHT / self.tower.txFreqInHertz)

            gainProduct = self.tower.txAntennaGain * RX_GAIN * self.tower.txPowerInWatts
            numerator = wavelength * math.sqrt(gainProduct / self.reading)

            distanceToUE = numerator / FOUR_PI
        else:
            # Use signal travel time
            distanceToUE = SPEED_OF_LIGHT * self.reading
        return distanceToUE

    # Add a range ring (centered on the associated tower's location)
    # to the KML object.
    def plot(self, kml, color):

        # First, plot the position of the associated tower.
        kml = self.tower.plot(kml)

        RING_THICKNESS = 10
        outerDistance = self.distance()

        # simplekml has some limitations. Therefore, we have to build
        # a 'circle' as a 36-sided polygon, and feed it to simplekml.
        outerCircle = polycircles.Polycircle(
            latitude=self.tower.latitude,
            longitude=self.tower.longitude,
            radius=outerDistance,
            number_of_vertices=36,
        )

        # Another limitation of simplekml is that it needs an outer AND
        # an inner definition of the polygon. To make a circle, we draw
        # two concentric 'circles' with the radius of the inner one slightly
        # smaller than the outer one.
        innerDistance = outerDistance - RING_THICKNESS
        innerCircle = polycircles.Polycircle(
            latitude=self.tower.latitude,
            longitude=self.tower.longitude,
            radius=innerDistance,
            number_of_vertices=36,
        )
        ring = kml.newpolygon(
            name=self.tower.id,
            outerboundaryis=outerCircle.to_kml(),
            innerboundaryis=innerCircle.to_kml(),
        )
        ring.style.polystyle.color = color
        return kml


def readDataFile(filename):
    # Initialize the set of towers and UE readings
    towers = []
    readings = []

    # Read the file, creating Tower and UEreading objects.
    try:
        # Towers read.
        towers = []

        # UE readings read.
        readings = []
        numReadings = 0

        # Open the file
        print("Reading {0}\n".format(filename))
        lines = open(filename, "r")

        # While not EOF do
        for line in lines:

            # Split the scan spec into tokens
            tokens = line.split()

            # If the first character of the first token is not '#' then
            # process the line. Otherwise, the line is a comment, and
            # should be ignored.
            if not tokens[0].startswith("#"):
                # If the input line specifies a cell tower, create a tower
                # object.
                if tokens[0] == "TWR":
                    towers.append(Tower(tokens[1:]))
                elif tokens[0] == "RDG":
                    # Otherwise the line represents a UE reading.
                    ueReading = UEreading(towers[numReadings], tokens[2:])
                    readings.append(ueReading)
                    numReadings += 1
                else:
                    print("Invalid line in file. First token is: " + tokens[0])
                    exit()

        # Close the file
        lines.close()
    except BaseException as ex:
        print("Error reading " + filename)
        print(ex.message)
        exit()

    return readings


###############################################################################
# Start of main program methods.
###############################################################################
# Parse the command-line arguments
def parseArgs():
    # Create an arg parser
    parser = argparse.ArgumentParser()

    # Add the command-line arguments to the parser.
    # Get the file which contains the cell tower coordinates and
    # RSS or time values
    parser.add_argument(
        "input_file",
        help="Filename (including path if not in the current directory)"
        + " containing the cell tower coordinates, and RSS values "
        + "or signal arrival time values at the mobile device.",
    )

    # This is the name of the output file containing the KML.
    parser.add_argument(
        "output_file",
        help="Filename (including path if not in the current directory)"
        + " to store the KML results. This filename should end with"
        + " a .kml extension.",
    )

    # Optional arguments:

    # Parse the commmand line arguments, and return them in an object.
    args = parser.parse_args()
    return args


############################################################################
# Start of main program
############################################################################

# Get command-line args
args = parseArgs()

readings = readDataFile(args.input_file)

# Initialize the simplekml object
kmlObject = simplekml.Kml()

# colors for the three range rings
colors = [simplekml.Color.red, simplekml.Color.white, simplekml.Color.blue]
colorIndex = 0

# For each UE reading, add the tower and range ring to the KML file.
for reading in readings:
    kmlObject = reading.plot(kmlObject, colors[colorIndex])
    colorIndex += 1

# Save the results in a KML file, which can be read by Google Earth Pro.
kmlObject.save(args.output_file)
