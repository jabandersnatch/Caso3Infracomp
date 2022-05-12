# %%
from tkinter import W
import numpy as np
import matplotlib.pyplot as plt

LOG_FILE_SYMMETRIC = 'app/src/main/resources/log_symmetric_time.txt'
LOG_FILE_ASYMMETRIC = 'app/src/main/resources/log_asymmetric_time.txt'

# create a np array that stores the time values
def create_np_array(file_name):
    with open(file_name, 'r') as f:
        lines = f.readlines()
        time_values = []
        for line in lines:
            # separate the line by the space
            line = line.split(' ')
            # append the last value to the list
            time_values.append(float(line[-1]))
        # convert the list to a np array
        # return the np array
        return time_values

symmetric_t = create_np_array(LOG_FILE_SYMMETRIC)

asymmetric_t = create_np_array(LOG_FILE_ASYMMETRIC)

fig, ax = plt.subplots(dpi=250)
ax.plot(symmetric_t, label='Symmetric')
# drow
ax.plot(asymmetric_t, label='Asymmetric')

ax.plot(np.array(asymmetric_t)-np.array(symmetric_t), label='Difference')
# change the ticks for the y axis to show less ticks
ax.yaxis.set_major_locator(plt.MaxNLocator(4))
ax.set_title('Time to run the iterative server in seconds')
ax.set_ylabel('Time (s)')
ax.set_xlabel('Iterations')
ax.legend()
plt.show()
# save the figure
fig.savefig('app/src/main/resources/timeGraphUnFiltered.png')
plt.close(fig)

