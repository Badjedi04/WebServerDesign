# Use an official Python runtime as a parent image
FROM python


# Set the working directory to /app
WORKDIR /app

COPY requirements.txt /app

# Copy the current directory contents into the container at /app
ADD ./WebServerDesign /app

# Install any needed packages specified in requirements.txt
RUN pip install --trusted-host pypi.python.org -r requirements.txt

# Make port 80 available to the world outside this container
EXPOSE 80



# Run Server.py.py when the container launches
CMD ["python", "Server.py"]
