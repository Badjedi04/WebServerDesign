# Use an official Python runtime as a parent image
FROM python

# Set the working directory to /app
WORKDIR /app

assignment1
COPY requirements.txt /app

# Copy the current directory contents into the container at /app
ADD . /app

# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt

COPY samples ./samples/
COPY public ./public/
COPY bootstrap.sh ./
RUN  chmod a+x bootstrap.sh
RUN  ./bootstrap.sh

COPY requirements.txt /app
# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Copy the current directory contents into the container at /app
COPY src ./src/
COPY Configuration ./Configuration/
COPY Main.py ./
main

# Make port 80 available to the world outside this container
EXPOSE 80

assignment1
# Define environment variable
ENV NAME World

# Run Server.py.py when the container launches
CMD ["python", "Server.py"]

# Run Server.py.py when the container launches
CMD ["python", "Main.py"]
main