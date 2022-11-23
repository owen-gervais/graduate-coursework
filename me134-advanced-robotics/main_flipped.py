# import the necessary packages
from imutils import resize
from PIL import ImageOps
import time
import dlib
import cv2

# Importing in the adafruit servo libraries
from adafruit_pca9685 import PCA9685
from adafruit_motor import servo
from adafruit_servokit import ServoKit


# The below function maps the position of the face
# to the servo angle for mapping on the phone
def correlateMvmt(pos_x):
    if pos_x > 95:
        servo_angle = 60
    elif pos_x < 30:
        servo_angle = 120
    else:
        servo_angle = -0.851*pos_x + 144
    return servo_angle


# The below function grabs the landmark positions on the eye
# from the data set and calculates the amount open of each
def generateDists(landmarks):
    t_l = landmarks.part(37).y
    t_r = landmarks.part(43).y
    b_l = landmarks.part(40).y
    b_r = landmarks.part(46).y
    dist_l = b_l -t_l
    dist_r = b_r -t_r
    return dist_l, dist_r


# isClosed correlates the distances and the time true to
# determine if the user has blinked or not
#
# TUNING PARAMETER: 3 in elif is the threshold for bool
#
def isClosed(dist_l, dist_r, loop_cnt):
    if loop_cnt > 3:
        loop_cnt = 0
        return True, loop_cnt 
    elif dist_l & dist_r < 3:
        return False, loop_cnt + 1 
    else:
        loop_cnt = 0
        return False, loop_cnt


# Create Instances of all of the servos and set to
# initial angles

kit = ServoKit(channels = 16)
kit.servo[0].set_pulse_width_range(400,2600)
kit.servo[1].set_pulse_width_range(400,2600)
tilt = kit.servo[0]
shoot = kit.servo[1]
tilt.angle = 90
shoot.angle = 90


# Create instances of the dlib frontal face detector and shape predictor
# with the 68point landmark data set

detector = dlib.get_frontal_face_detector()
predictor = dlib.shape_predictor("shape_predictor_68_face_landmarks.dat")

# Start the video stream from the device

cap = cv2.VideoCapture(0)

# Give the camera sensor time to warm up

time.sleep(2.0)

# Initialize variable used for monitoring the blink time 

loop_cnt = 0

# Loop over the frames from the video stream

while True:
    # grab the frame from the video stream, resize it to have a
    # maximum width of 200 pixels, and convert it to grayscale
    _,frame = cap.read()
    
    frame = cv2.flip(frame, 0)
    
    frame =resize(frame, width=200)
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    # detect faces in the grayscale frame
    faces = detector(gray, 0)
    
    # Iterate through the faces detected and calculate the reference point for tracking
    for face in faces:
        f_l = face.left()
        
        # move to the tilt angle 
        tilt.angle = correlateMvmt(f_l)
        time.sleep(.01)
        
        # generate all of the landmarks
        eye_landmarks = predictor(gray, face)
        
        # Calculate the distances 
        dist_R, dist_L = generateDists(eye_landmarks)
        
        # Determine if eyes are closed
        closed, loop_cnt = isClosed(dist_R, dist_L, loop_cnt)
        
        # Actuate the clicker
        if closed:
            shoot.angle = 0
            time.sleep(.01)
        else:
            shoot.angle = 90
            time.sleep(.01)
    
    # show the frame
    cv2.imshow("Frame", frame)

    key = cv2.waitKey(1) & 0xFF
    # if the `q` key was pressed, break from the loop
    if key == ord("q"):
        break
    
# Cleanup
cap.release()
cv2.destroyAllWindows()